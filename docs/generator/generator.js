// The config generator: a form per CRD, rendered from the openAPIV3Schema that
// scripts/docs-schemas.sh exports into schemas.js, and the YAML it describes.
//
// One document per kind lives in `docs`; the form writes into it by path, and every change
// re-validates against the same schema and re-prints the YAML. A structural change (adding a
// block, an item, a key) re-renders the form; typing in a field does not, so focus is never lost
// mid-word. Nothing leaves the browser: the draft is kept in localStorage, per kind.
(() => {
  'use strict';

  const CRDS = window.WEEBO_CRDS || [];
  const YAML = window.jsyaml;
  const STORE = 'weebo-si-generator:v1:';
  const DOCS = 'https://github.com/batleforc/weebo-si-hardening/blob/main/docs/';
  const DOC_PAGES = {
    WeeboSiConfig: 'weebosiconfig.md',
    WeeboSiTeam: 'weebositeam.md',
    WeeboSiUser: 'weebosiuser.md',
  };
  // The operator reads exactly one WeeboSiConfig: `cluster` (crates/weebo-si-crd SINGLETON_NAME).
  const SINGLETON = { WeeboSiConfig: 'cluster' };
  const DNS_SUBDOMAIN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;

  const $ = (id) => document.getElementById(id);
  const form = $('form');
  const yamlOut = $('yaml');
  const status = $('status');

  // ---- state ------------------------------------------------------------------------------------

  const byKind = Object.fromEntries(CRDS.map((crd) => [crd.kind, crd]));
  const docs = {};
  // kind -> Set of path keys whose <details> the user opened / closed. A required block is open
  // unless closed; an optional one is closed unless opened.
  const open = {};
  const shut = {};
  let kind = CRDS.length ? CRDS[0].kind : '';
  let fields = new Map(); // path key -> { el, error } for the field showing that path's errors
  let groups = new Map(); // path key -> <details> for that object/list/map
  let parseErrors = new Map(); // path key -> message, from free-form YAML fields
  let lastErrors = [];
  let uid = 0;

  const pk = (path) => JSON.stringify(path);
  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

  function storage(fn) {
    try { return fn(window.localStorage); } catch { return undefined; }
  }

  function blankDoc(k) {
    return { metadata: SINGLETON[k] ? { name: SINGLETON[k] } : {}, spec: {} };
  }

  function loadDoc(k) {
    const saved = storage((s) => s.getItem(STORE + k));
    if (saved) {
      try {
        const doc = JSON.parse(saved);
        if (isObj(doc) && isObj(doc.metadata) && isObj(doc.spec)) return doc;
      } catch { /* a corrupt draft is dropped, not fatal */ }
    }
    return blankDoc(k);
  }

  function saveDoc(k) {
    storage((s) => s.setItem(STORE + k, JSON.stringify(docs[k])));
  }

  // The object the form edits: the CRD's `spec`, plus the part of `metadata` a cluster-scoped
  // object needs. apiVersion and kind are fixed per tab and only added to the output.
  function rootSchema(crd) {
    const labels = {
      type: 'object',
      additionalProperties: { type: 'string' },
    };
    return {
      type: 'object',
      required: ['metadata', 'spec'],
      properties: {
        metadata: {
          type: 'object',
          required: ['name'],
          description: `Standard object metadata. ${crd.kind} is cluster-scoped, so there is no namespace.`,
          properties: {
            name: {
              type: 'string',
              maxLength: 253,
              description: SINGLETON[crd.kind]
                ? `Must be \`${SINGLETON[crd.kind]}\`: the operator reads that one object and reports any other as \`Degraded\`.`
                : 'The object\'s name: a DNS subdomain (lower-case letters, digits, `-` and `.`).',
            },
            labels: { ...labels, description: 'Labels on the object itself.' },
            annotations: { ...labels, description: 'Annotations on the object itself.' },
          },
        },
        spec: crd.schema.properties.spec,
      },
    };
  }

  // ---- paths ------------------------------------------------------------------------------------

  function get(root, path) {
    let node = root;
    for (const key of path) {
      if (node === null || typeof node !== 'object') return undefined;
      node = node[key];
    }
    return node;
  }

  function set(root, path, value) {
    let node = root;
    for (let i = 0; i < path.length - 1; i += 1) {
      const key = path[i];
      if (node[key] === null || typeof node[key] !== 'object') {
        node[key] = typeof path[i + 1] === 'number' ? [] : {};
      }
      node = node[key];
    }
    node[path[path.length - 1]] = value;
  }

  function del(root, path) {
    const parent = get(root, path.slice(0, -1));
    const key = path[path.length - 1];
    if (Array.isArray(parent)) parent.splice(key, 1);
    else if (isObj(parent)) delete parent[key];
  }

  // ---- schema helpers ---------------------------------------------------------------------------

  function shape(schema) {
    const type = schema.type;
    if (type === 'object' || (!type && schema.properties)) {
      if (schema.properties) return 'group';
      if (isObj(schema.additionalProperties)) return 'map';
      return 'free';
    }
    if (type === 'array') return 'list';
    if (type === 'boolean') return 'bool';
    if (type === 'integer' || type === 'number') return 'number';
    if (Array.isArray(schema.enum)) return 'enum';
    return 'string';
  }

  function emptyValue(schema) {
    switch (shape(schema)) {
      case 'group': case 'map': case 'free': return {};
      case 'list': return [];
      default: return undefined;
    }
  }

  // What a new list item or map entry starts as: an empty block, or an empty scalar the
  // validation then asks the user to fill in.
  function blank(schema) {
    const value = emptyValue(schema);
    if (value !== undefined) return value;
    const s = shape(schema);
    if (s === 'number') return 0;
    if (s === 'bool') return false;
    return '';
  }

  // Required objects exist as soon as their parent does, so their own fields show up at once.
  function ensureRequired(schema, value) {
    if (shape(schema) !== 'group' || !isObj(value)) return;
    for (const name of schema.required || []) {
      const child = schema.properties[name];
      if (child && value[name] === undefined && ['group', 'map', 'free'].includes(shape(child))) {
        value[name] = {};
      }
    }
    for (const [name, child] of Object.entries(schema.properties)) {
      if (value[name] !== undefined) ensureRequired(child, value[name]);
    }
  }

  function typeLabel(schema) {
    const s = shape(schema);
    if (s === 'group') return 'object';
    if (s === 'map') return `map of ${shape(schema.additionalProperties) === 'group' ? 'object' : typeLabel(schema.additionalProperties)}`;
    if (s === 'free') return 'free-form';
    if (s === 'list') return `list of ${typeLabel(schema.items || {})}`;
    if (s === 'enum') return 'one of';
    return schema.format ? `${schema.type} · ${schema.format}` : schema.type || 'string';
  }

  function short(value) {
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    return text.length > 40 ? `${text.slice(0, 39)}…` : text;
  }

  // ---- description rendering ---------------------------------------------------------------------

  function escapeHtml(text) {
    return text.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function inline(text) {
    return escapeHtml(text.replace(/\s*\n\s*/g, ' '))
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>');
  }

  function describe(text) {
    const box = document.createElement('div');
    box.className = 'desc';
    if (!text) return box;
    const paragraphs = text.trim().split(/\n\s*\n/);
    const first = document.createElement('p');
    first.innerHTML = inline(paragraphs[0]); // escaped in inline()
    box.append(first);
    if (paragraphs.length > 1) {
      const more = document.createElement('details');
      const summary = document.createElement('summary');
      summary.textContent = 'more';
      more.append(summary);
      for (const para of paragraphs.slice(1)) {
        const p = document.createElement('p');
        p.innerHTML = inline(para);
        more.append(p);
      }
      more.addEventListener('toggle', () => { summary.textContent = more.open ? 'less' : 'more'; });
      box.append(more);
    }
    return box;
  }

  // ---- rendering ----------------------------------------------------------------------------------

  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else if (value !== undefined && value !== false) node.setAttribute(key, value === true ? '' : value);
    }
    node.append(...children.filter(Boolean));
    return node;
  }

  function head(label, schema, opts, forId) {
    const meta = el('span', { class: 'field-meta' });
    if (opts.required) meta.append(el('span', { class: 'tag req', text: 'required' }));
    meta.append(el('span', { class: 'tag', text: typeLabel(schema) }));
    if (schema.default !== undefined && !isObj(schema.default)) {
      meta.append(el('span', { class: 'tag', text: `default ${short(schema.default)}` }));
    }
    const name = forId
      ? el('label', { class: 'field-name', for: forId, text: label })
      : el('span', { class: 'field-name', text: label });
    return el('div', { class: 'field-head' }, name, meta);
  }

  function doc() { return docs[kind]; }

  function structural(openPath) {
    if (openPath) { open[kind].add(pk(openPath)); shut[kind].delete(pk(openPath)); }
    render();
  }

  function render() {
    const crd = byKind[kind];
    const root = rootSchema(crd);
    fields = new Map();
    groups = new Map();
    parseErrors = new Map();
    ensureRequired(root, doc());
    const fragment = document.createDocumentFragment();
    for (const name of Object.keys(root.properties)) {
      fragment.append(node(root.properties[name], [name], { label: name, required: true }));
    }
    form.replaceChildren(fragment);
    refresh();
  }

  function node(schema, path, opts) {
    const s = shape(schema);
    const value = get(doc(), path);
    if (value === undefined && ['group', 'map', 'free', 'list'].includes(s) && !opts.required && !opts.compact) {
      return absent(schema, path, opts);
    }
    switch (s) {
      case 'group': return group(schema, path, opts);
      case 'map': return map(schema, path, opts);
      case 'list': return list(schema, path, opts);
      case 'free': return free(schema, path, opts);
      default: return scalar(schema, path, opts);
    }
  }

  // An optional block that is not set: a dashed row with its description and an Add button.
  function absent(schema, path, opts) {
    const add = el('button', {
      type: 'button',
      class: 'btn small add',
      text: shape(schema) === 'list' ? '+ Add item' : '+ Add',
      'aria-label': `Add ${opts.label}`,
      onclick: () => {
        if (shape(schema) === 'list') {
          set(doc(), path, [blank(schema.items || {})]);
          open[kind].add(pk([...path, 0]));
        } else {
          set(doc(), path, emptyValue(schema));
        }
        structural(path);
      },
    });
    const box = el('div', { class: 'field absent' }, head(opts.label, schema, opts), describe(schema.description), el('div', {}, add));
    box.dataset.path = pk(path);
    fields.set(pk(path), { el: box, error: null });
    return box;
  }

  function details(schema, path, opts, body) {
    const key = pk(path);
    const summary = el('summary', {}, head(opts.label, schema, opts));
    const badge = el('span', { class: 'group-badge' });
    summary.querySelector('.field-meta').prepend(badge);
    if (opts.removable) {
      summary.querySelector('.field-meta').append(el('button', {
        type: 'button',
        class: 'btn small remove',
        text: 'Remove',
        'aria-label': `Remove ${opts.label}`,
        onclick: (event) => {
          event.preventDefault();
          event.stopPropagation();
          del(doc(), path);
          open[kind].delete(key);
          structural();
        },
      }));
    } else if (!opts.required && !opts.compact) {
      summary.querySelector('.field-meta').append(el('button', {
        type: 'button',
        class: 'btn small remove',
        text: 'Unset',
        'aria-label': `Unset ${opts.label}`,
        onclick: (event) => {
          event.preventDefault();
          event.stopPropagation();
          del(doc(), path);
          open[kind].delete(key);
          structural();
        },
      }));
    }
    if (!opts.compact) summary.append(describe(schema.description));
    const isOpen = open[kind].has(key) || (opts.required && !opts.compact && !shut[kind].has(key));
    const box = el('details', { class: 'group', open: isOpen }, summary, el('div', { class: 'children' }, ...body()));
    box.dataset.path = key;
    box.addEventListener('toggle', () => {
      if (box.open) { open[kind].add(key); shut[kind].delete(key); } else { open[kind].delete(key); shut[kind].add(key); }
    });
    groups.set(key, { box, badge });
    return box;
  }

  function group(schema, path, opts) {
    return details(schema, path, opts, () => Object.keys(schema.properties).map((name) => node(
      schema.properties[name],
      [...path, name],
      { label: name, required: (schema.required || []).includes(name) },
    )));
  }

  function list(schema, path, opts) {
    const items = schema.items || { type: 'string' };
    const itemShape = shape(items);
    return details(schema, path, { ...opts, label: `${opts.label} [${(get(doc(), path) || []).length}]` }, () => {
      const values = get(doc(), path) || [];
      const rows = values.map((_, index) => {
        const itemPath = [...path, index];
        if (['group', 'map', 'free', 'list'].includes(itemShape)) {
          return node(items, itemPath, { label: `${opts.label}[${index}]`, required: true, compact: true, removable: true });
        }
        return el('div', { class: 'row' },
          node(items, itemPath, { label: `${opts.label}[${index}]`, required: true, compact: true }),
          el('button', {
            type: 'button', class: 'btn small remove', text: '✕', 'aria-label': `Remove ${opts.label}[${index}]`,
            onclick: () => { del(doc(), itemPath); structural(); },
          }));
      });
      const add = el('button', {
        type: 'button', class: 'btn small add', text: '+ Add item',
        onclick: () => {
          const current = get(doc(), path) || [];
          current.push(blank(items));
          set(doc(), path, current);
          structural([...path, current.length - 1]);
        },
      });
      return [el('div', { class: 'rows' }, ...rows), el('div', {}, add)];
    });
  }

  function map(schema, path, opts) {
    const values = schema.additionalProperties;
    const valueShape = shape(values);
    return details(schema, path, opts, () => {
      const current = get(doc(), path) || {};
      const rows = Object.keys(current).map((key) => {
        const entryPath = [...path, key];
        const keyInput = el('input', {
          type: 'text', value: key, placeholder: 'key', 'aria-label': `${opts.label} key`,
          onchange: () => {
            const next = keyInput.value.trim();
            if (next === key) return;
            const target = get(doc(), path);
            if (Object.hasOwn(target, next)) {
              keyInput.value = key;
              keyInput.classList.add('flash');
              return;
            }
            // Rebuilt rather than renamed in place, so the entry keeps its position.
            const renamed = {};
            for (const [k, v] of Object.entries(target)) renamed[k === key ? next : k] = v;
            set(doc(), path, renamed);
            structural();
          },
        });
        fields.set(pk(entryPath) + '#key', { el: keyInput, error: null });
        const remove = el('button', {
          type: 'button', class: 'btn small remove', text: '✕', 'aria-label': `Remove ${opts.label} ${key}`,
          onclick: () => { del(doc(), entryPath); structural(); },
        });
        if (['group', 'map', 'free', 'list'].includes(valueShape)) {
          return el('div', { class: 'row' },
            el('div', { class: 'rows' }, keyInput, node(values, entryPath, { label: key || '(new key)', required: true, compact: true })),
            remove);
        }
        return el('div', { class: 'row kv' }, keyInput, node(values, entryPath, { label: key, required: true, compact: true }), remove);
      });
      const add = el('button', {
        type: 'button', class: 'btn small add', text: '+ Add entry',
        onclick: () => {
          const target = get(doc(), path) || {};
          let key = '';
          for (let n = 1; Object.hasOwn(target, key); n += 1) key = `key-${n}`;
          target[key] = blank(values);
          set(doc(), path, target);
          structural([...path, key]);
          fields.get(pk([...path, key]) + '#key')?.el.focus();
        },
      });
      return [el('div', { class: 'rows' }, ...rows), el('div', {}, add)];
    });
  }

  // `x-kubernetes-preserve-unknown-fields`: the schema says nothing, so the value is YAML.
  function free(schema, path, opts) {
    const id = `f${uid += 1}`;
    const value = get(doc(), path);
    const area = el('textarea', {
      id, rows: 5, spellcheck: 'false', placeholder: 'key: value',
    });
    area.value = value && Object.keys(value).length ? YAML.dump(value, { lineWidth: -1 }) : '';
    const error = el('div', { class: 'error', role: 'status' });
    const box = el('div', { class: 'field' }, head(opts.label, schema, opts, id), describe(schema.description), area, error);
    area.addEventListener('input', () => {
      const key = pk(path);
      parseErrors.delete(key);
      if (!area.value.trim()) {
        if (opts.required) set(doc(), path, {}); else del(doc(), path);
      } else {
        try {
          const parsed = YAML.load(area.value);
          if (!isObj(parsed)) throw new Error('must be a mapping (key: value)');
          set(doc(), path, parsed);
        } catch (err) {
          parseErrors.set(key, `invalid YAML: ${String(err.message || err).split('\n')[0]}`);
        }
      }
      refresh();
    });
    box.dataset.path = pk(path);
    fields.set(pk(path), { el: box, error, control: area });
    return box;
  }

  function scalar(schema, path, opts) {
    const id = `f${uid += 1}`;
    const s = shape(schema);
    const value = get(doc(), path);
    let control;
    const write = (next) => {
      if (next === undefined) {
        if (opts.compact) set(doc(), path, s === 'number' ? 0 : ''); else del(doc(), path);
      } else {
        set(doc(), path, next);
      }
      refresh();
    };

    if (s === 'enum') {
      control = el('select', { id });
      const unset = opts.required
        ? 'choose…'
        : schema.default !== undefined ? `unset (default ${short(schema.default)})` : 'unset';
      control.append(el('option', { value: '', text: `— ${unset} —` }));
      for (const option of schema.enum) {
        if (option === null) continue;
        control.append(el('option', { value: option, text: option }));
      }
      control.value = value ?? '';
      control.addEventListener('change', () => write(control.value === '' ? undefined : control.value));
    } else if (s === 'bool') {
      control = el('div', { class: 'bool', role: 'radiogroup', 'aria-label': opts.label });
      const choices = opts.required ? ['true', 'false'] : ['unset', 'true', 'false'];
      for (const choice of choices) {
        const radio = el('input', { type: 'radio', name: id, value: choice, id: `${id}-${choice}` });
        radio.checked = choice === (value === undefined ? 'unset' : String(value));
        radio.addEventListener('change', () => write(choice === 'unset' ? undefined : choice === 'true'));
        const text = choice === 'unset' && schema.default !== undefined ? `unset (${schema.default})` : choice;
        control.append(el('label', {}, radio, el('span', { text })));
      }
    } else if (s === 'number') {
      control = el('input', {
        id, type: 'number', inputmode: 'numeric', step: schema.type === 'integer' ? 1 : 'any',
        min: schema.minimum, max: schema.maximum,
        placeholder: schema.default !== undefined ? String(schema.default) : '',
      });
      control.value = value ?? '';
      control.addEventListener('input', () => {
        const raw = control.value.trim();
        write(raw === '' ? undefined : Number(raw));
      });
    } else {
      control = el('input', {
        id, type: 'text', spellcheck: 'false',
        placeholder: schema.default !== undefined ? String(schema.default) : schema.format || '',
        maxlength: schema.maxLength,
      });
      control.value = value ?? '';
      control.addEventListener('input', () => write(control.value === '' ? undefined : control.value));
    }

    const error = el('div', { class: 'error', role: 'status' });
    if (opts.compact) {
      const box = el('div', { class: 'compact' }, control, error);
      box.dataset.path = pk(path);
    fields.set(pk(path), { el: box, error, control });
      return box;
    }
    const box = el('div', { class: 'field' }, head(opts.label, schema, opts, s === 'bool' ? null : id), describe(schema.description), control, error);
    box.dataset.path = pk(path);
    fields.set(pk(path), { el: box, error, control });
    return box;
  }

  // ---- validation -------------------------------------------------------------------------------

  function validate(schema, value, path, out) {
    if (value === undefined || value === null) return;
    const s = shape(schema);
    const fail = (msg) => out.errors.push({ path, msg });
    if (s === 'group' || s === 'map' || s === 'free') {
      if (!isObj(value)) return fail('must be an object');
      const props = schema.properties || {};
      for (const name of schema.required || []) {
        if (value[name] === undefined) out.errors.push({ path: [...path, name], msg: 'required' });
      }
      for (const [key, child] of Object.entries(value)) {
        if (props[key]) validate(props[key], child, [...path, key], out);
        else if (isObj(schema.additionalProperties)) {
          if (key === '') out.errors.push({ path: [...path, key], msg: 'key must not be empty' });
          validate(schema.additionalProperties, child, [...path, key], out);
        } else if (!schema['x-kubernetes-preserve-unknown-fields'] && schema.additionalProperties !== true && s === 'group') {
          out.warnings.push({ path: [...path, key], msg: 'not in the schema — the API server drops it, and so does this output' });
        }
      }
      return;
    }
    if (s === 'list') {
      if (!Array.isArray(value)) return fail('must be a list');
      if (schema.minItems !== undefined && value.length < schema.minItems) fail(`needs at least ${schema.minItems} item(s)`);
      if (schema.maxItems !== undefined && value.length > schema.maxItems) fail(`at most ${schema.maxItems} item(s)`);
      value.forEach((item, index) => validate(schema.items || {}, item, [...path, index], out));
      return;
    }
    if (s === 'bool') {
      if (typeof value !== 'boolean') fail('must be true or false');
      return;
    }
    if (s === 'number') {
      if (typeof value !== 'number' || Number.isNaN(value)) return fail('must be a number');
      if (schema.type === 'integer' && !Number.isInteger(value)) fail('must be a whole number');
      if (schema.minimum !== undefined && value < schema.minimum) fail(`must be ≥ ${schema.minimum}`);
      if (schema.maximum !== undefined && value > schema.maximum) fail(`must be ≤ ${schema.maximum}`);
      return;
    }
    if (typeof value !== 'string') return fail('must be a string');
    if (Array.isArray(schema.enum) && !schema.enum.includes(value)) fail(`must be one of ${schema.enum.filter((v) => v !== null).join(', ')}`);
    if (schema.minLength !== undefined && value.length < schema.minLength) fail(`at least ${schema.minLength} character(s)`);
    if (schema.maxLength !== undefined && value.length > schema.maxLength) fail(`at most ${schema.maxLength} characters`);
    if (schema.pattern) {
      try {
        if (!new RegExp(schema.pattern, 'u').test(value)) fail(`must match ${schema.pattern}`);
      } catch { /* a pattern this browser cannot compile is left to the API server */ }
    }
  }

  function check(k) {
    const crd = byKind[k];
    const value = docs[k];
    const out = { errors: [], warnings: [] };
    validate(rootSchema(crd), value, [], out);
    const name = value.metadata?.name;
    if (name === undefined || name === '') {
      if (!out.errors.some((e) => pk(e.path) === pk(['metadata', 'name']))) {
        out.errors.push({ path: ['metadata', 'name'], msg: 'required' });
      }
    } else {
      if (SINGLETON[k] && name !== SINGLETON[k]) {
        out.errors.push({ path: ['metadata', 'name'], msg: `must be "${SINGLETON[k]}" — any other ${k} is ignored` });
      } else if (!DNS_SUBDOMAIN.test(name)) {
        out.errors.push({ path: ['metadata', 'name'], msg: 'must be a DNS subdomain: lower-case letters, digits, "-" and "."' });
      }
    }
    if (k === kind) {
      for (const [key, msg] of parseErrors) out.errors.push({ path: JSON.parse(key), msg });
    }
    return out;
  }

  // ---- output -----------------------------------------------------------------------------------

  // Keys in schema order, unknown keys dropped (they were warned about), maps in the user's order.
  function normalize(schema, value) {
    if (value === undefined || value === null) return undefined;
    const s = shape(schema);
    if (s === 'group' && isObj(value)) {
      const out = {};
      for (const name of Object.keys(schema.properties)) {
        const child = normalize(schema.properties[name], value[name]);
        if (child !== undefined) out[name] = child;
      }
      if (isObj(schema.additionalProperties)) {
        for (const [key, child] of Object.entries(value)) {
          if (!schema.properties[key]) out[key] = normalize(schema.additionalProperties, child);
        }
      }
      return out;
    }
    if (s === 'map' && isObj(value)) {
      const out = {};
      for (const [key, child] of Object.entries(value)) out[key] = normalize(schema.additionalProperties, child);
      return out;
    }
    if (s === 'list' && Array.isArray(value)) return value.map((item) => normalize(schema.items || {}, item));
    return value;
  }

  function output() {
    const crd = byKind[kind];
    const root = rootSchema(crd);
    const body = normalize(root, doc());
    return YAML.dump({
      apiVersion: `${crd.group}/${crd.version}`,
      kind: crd.kind,
      metadata: body.metadata,
      spec: body.spec || {},
    }, { lineWidth: -1, noRefs: true });
  }

  function highlight(text) {
    return text.split('\n').map((line) => {
      const m = /^(\s*(?:- )*)((?:[^\s:#'"-][^:]*|'[^']*'|"[^"]*")):(?=\s|$)(.*)$/.exec(line);
      if (m) return `${escapeHtml(m[1])}<span class="k">${escapeHtml(m[2])}</span>:${value(m[3])}`;
      const item = /^(\s*- )(.*)$/.exec(line);
      if (item) return escapeHtml(item[1]) + value(` ${item[2]}`).replace(/^ /, '');
      return escapeHtml(line);
    }).join('\n');

    function value(rest) {
      const v = rest.trim();
      if (!v) return escapeHtml(rest);
      const cls = /^(-?\d+(\.\d+)?|true|false|null|\{\}|\[\])$/.test(v) ? 'n' : 's';
      return ` <span class="${cls}">${escapeHtml(v)}</span>`;
    }
  }

  function fileName() {
    const name = doc().metadata?.name || 'unnamed';
    return `${kind.toLowerCase()}-${name}.yaml`;
  }

  // ---- refresh: errors, status, YAML --------------------------------------------------------------

  function fieldFor(path) {
    for (let n = path.length; n > 0; n -= 1) {
      const hit = fields.get(pk(path.slice(0, n)));
      if (hit && hit.error) return hit;
      const grp = groups.get(pk(path.slice(0, n)));
      if (grp) return null;
    }
    return null;
  }

  function refresh() {
    const result = check(kind);
    lastErrors = result.errors;

    for (const { el: box, error } of fields.values()) {
      if (error) error.textContent = '';
      box.classList?.remove('invalid');
    }
    const counts = new Map();
    for (const { box, badge } of groups.values()) {
      box.classList.remove('invalid');
      badge.textContent = '';
    }
    for (const err of result.errors) {
      const field = fieldFor(err.path);
      if (field) {
        field.error.textContent = field.error.textContent ? `${field.error.textContent}; ${err.msg}` : err.msg;
        field.el.classList.add('invalid');
      }
      for (let n = err.path.length - 1; n > 0; n -= 1) {
        const key = pk(err.path.slice(0, n));
        if (groups.has(key)) counts.set(key, (counts.get(key) || 0) + 1);
      }
    }
    for (const [key, count] of counts) {
      const { box, badge } = groups.get(key);
      box.classList.add('invalid');
      badge.textContent = `${count} ✕`;
    }

    renderStatus(result);
    const text = output();
    yamlOut.innerHTML = highlight(text); // every piece escaped in highlight()
    $('dry-run').textContent = `kubectl apply --dry-run=server -f ${fileName()}`;
    renderTabs();
    saveDoc(kind);
  }

  function label(path) {
    return path.map((p, i) => (typeof p === 'number' ? `[${p}]` : i ? `.${p}` : p)).join('') || '(root)';
  }

  function renderStatus({ errors, warnings }) {
    status.replaceChildren();
    if (!errors.length && !warnings.length) {
      status.append(el('span', { class: 'ok', text: '✓ valid against the schema' }));
      return;
    }
    const block = (items, cls, title) => {
      if (!items.length) return;
      const ul = el('ul');
      for (const item of items.slice(0, 50)) {
        ul.append(el('li', {}, el('button', {
          type: 'button', text: label(item.path), onclick: () => reveal(item.path),
        }), document.createTextNode(` — ${item.msg}`)));
      }
      if (items.length > 50) ul.append(el('li', { text: `…and ${items.length - 50} more` }));
      status.append(el('div', { class: cls }, el('span', { class: 'title', text: title }), ul));
    };
    block(errors, 'errors', `${errors.length} error${errors.length > 1 ? 's' : ''}`);
    block(warnings, 'warnings', `${warnings.length} warning${warnings.length > 1 ? 's' : ''}`);
  }

  // Open every enclosing block, then focus and flash the field.
  function reveal(path) {
    let changed = false;
    for (let n = 1; n < path.length; n += 1) {
      const key = pk(path.slice(0, n));
      if (!open[kind].has(key) || shut[kind].has(key)) { open[kind].add(key); shut[kind].delete(key); changed = true; }
    }
    if (changed) render();
    let target = null;
    for (let n = path.length; n > 0 && !target; n -= 1) {
      target = fields.get(pk(path.slice(0, n))) || null;
      if (!target && groups.get(pk(path.slice(0, n)))) target = { el: groups.get(pk(path.slice(0, n))).box };
    }
    if (!target) return;
    target.el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    target.el.classList.remove('flash');
    void target.el.offsetWidth; // restart the animation
    target.el.classList.add('flash');
    const focusable = target.control || target.el.querySelector('input, select, textarea, summary');
    focusable?.focus({ preventScroll: true });
  }

  // ---- tabs, actions ------------------------------------------------------------------------------

  function renderTabs() {
    const tabs = $('tabs');
    if (!tabs.childElementCount) {
      for (const crd of CRDS) {
        tabs.append(el('button', {
          type: 'button', role: 'tab', class: 'tab', id: `tab-${crd.kind}`, 'data-kind': crd.kind,
          onclick: () => select(crd.kind),
        }, document.createTextNode(crd.kind), el('span', { class: 'count' })));
      }
      tabs.addEventListener('keydown', (event) => {
        if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
        const kinds = CRDS.map((c) => c.kind);
        const next = kinds[(kinds.indexOf(kind) + (event.key === 'ArrowRight' ? 1 : kinds.length - 1)) % kinds.length];
        select(next);
        $(`tab-${next}`).focus();
      });
    }
    for (const tab of tabs.children) {
      const k = tab.dataset.kind;
      const selected = k === kind;
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
      const errors = k === kind ? lastErrors.length : check(k).errors.length;
      tab.querySelector('.count').textContent = errors ? `${errors} ✕` : '';
    }
  }

  function select(k) {
    if (!byKind[k]) return;
    kind = k;
    if (window.location.hash !== `#${k}`) history.replaceState(null, '', `#${k}`);
    const crd = byKind[k];
    $('doc-link').href = DOCS + (DOC_PAGES[k] || '');
    $('doc-link').textContent = `${k} reference`;
    const about = crd.schema.description || crd.schema.properties.spec.description || '';
    $('kind-summary').innerHTML = `<code>${escapeHtml(crd.group)}/${escapeHtml(crd.version)}</code> · ${escapeHtml(crd.scope)}-scoped · plural <code>${escapeHtml(crd.plural)}</code>${about ? ` — ${inline(about.split(/\n\s*\n/)[0])}` : ''}`;
    render();
  }

  function openAll(k, schema, value, path) {
    if (!isObj(value) && !Array.isArray(value)) return;
    const s = shape(schema);
    if (!['group', 'map', 'list'].includes(s)) return;
    if (path.length) open[k].add(pk(path));
    if (s === 'group') for (const name of Object.keys(schema.properties)) openAll(k, schema.properties[name], value[name], [...path, name]);
    if (s === 'map') for (const key of Object.keys(value)) openAll(k, schema.additionalProperties, value[key], [...path, key]);
    if (s === 'list') value.forEach((item, i) => openAll(k, schema.items || {}, item, [...path, i]));
  }

  function wire() {
    $('expand-all').addEventListener('click', () => {
      shut[kind].clear();
      openAll(kind, rootSchema(byKind[kind]), doc(), []);
      render();
    });
    $('collapse-all').addEventListener('click', () => {
      open[kind].clear();
      shut[kind] = new Set(groups.keys());
      render();
    });
    $('reset').addEventListener('click', () => {
      if (!window.confirm(`Clear the ${kind} form?`)) return;
      docs[kind] = blankDoc(kind);
      open[kind] = new Set();
      shut[kind] = new Set();
      render();
    });
    $('copy').addEventListener('click', async () => {
      const button = $('copy');
      try {
        await navigator.clipboard.writeText(output());
        button.textContent = 'Copied';
      } catch {
        const range = document.createRange();
        range.selectNodeContents(yamlOut);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        button.textContent = 'Selected — press Ctrl+C';
      }
      setTimeout(() => { button.textContent = 'Copy'; }, 1600);
    });
    $('download').addEventListener('click', () => {
      const url = URL.createObjectURL(new Blob([output()], { type: 'application/yaml' }));
      const link = el('a', { href: url, download: fileName() });
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    $('import-toggle').addEventListener('click', () => {
      const panel = $('import');
      panel.hidden = !panel.hidden;
      $('import-toggle').setAttribute('aria-expanded', String(!panel.hidden));
      if (!panel.hidden) $('import-text').focus();
    });
    $('import-apply').addEventListener('click', () => {
      const error = $('import-error');
      error.textContent = '';
      let parsed;
      try {
        parsed = YAML.load($('import-text').value);
      } catch (err) {
        error.textContent = `invalid YAML: ${String(err.message || err).split('\n')[0]}`;
        return;
      }
      if (!isObj(parsed) || !byKind[parsed.kind]) {
        error.textContent = `kind must be one of ${CRDS.map((c) => c.kind).join(', ')}`;
        return;
      }
      const crd = byKind[parsed.kind];
      const expected = `${crd.group}/${crd.version}`;
      if (parsed.apiVersion && parsed.apiVersion !== expected) {
        error.textContent = `note: apiVersion ${parsed.apiVersion} was replaced by ${expected}`;
      }
      const metadata = isObj(parsed.metadata) ? parsed.metadata : {};
      docs[crd.kind] = {
        metadata: Object.fromEntries(['name', 'labels', 'annotations'].filter((k) => metadata[k] !== undefined).map((k) => [k, metadata[k]])),
        spec: isObj(parsed.spec) ? parsed.spec : {},
      };
      open[crd.kind] = new Set();
      shut[crd.kind] = new Set();
      openAll(crd.kind, rootSchema(crd), docs[crd.kind], []);
      $('import').hidden = true;
      $('import-toggle').setAttribute('aria-expanded', 'false');
      select(crd.kind);
    });
    window.addEventListener('hashchange', () => {
      const k = window.location.hash.slice(1);
      if (k !== kind && byKind[k]) select(k);
    });
  }

  // ---- boot ---------------------------------------------------------------------------------------

  if (!CRDS.length || !YAML) {
    form.textContent = !CRDS.length
      ? 'schemas.js is missing or empty — run `task docs:schemas`.'
      : 'The YAML library did not load (offline, or blocked). The form needs it to print and import YAML.';
    return;
  }
  for (const crd of CRDS) {
    docs[crd.kind] = loadDoc(crd.kind);
    open[crd.kind] = new Set();
    shut[crd.kind] = new Set();
  }
  wire();
  const fromHash = window.location.hash.slice(1);
  select(byKind[fromHash] ? fromHash : kind);
})();
