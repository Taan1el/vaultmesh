import { useState, type FormEvent } from 'react';
import type { CreateSecretDto } from '../../../shared/types';

interface CreateSecretFormProps {
  disabled: boolean;
  onCreate: (dto: CreateSecretDto) => Promise<boolean>;
}

const sampleForm = {
  path: 'secret/apps/reporting',
  name: 'Reporting API token',
  description: 'Token used by the reporting worker',
  plaintext: '{"token":"example-token-not-real","scope":"reports:read"}',
  isDynamic: false,
  ttlSeconds: 60,
};

const emptyForm = { ...sampleForm, path: '', name: '', description: '', plaintext: '' };

export function CreateSecretForm({ disabled, onCreate }: CreateSecretFormProps) {
  const [form, setForm] = useState(sampleForm);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const created = await onCreate({
      path: form.path,
      name: form.name,
      description: form.description,
      plaintext: form.plaintext,
      isDynamic: form.isDynamic,
      ttlSeconds: form.isDynamic ? form.ttlSeconds : undefined,
    });
    if (created) {
      setForm(emptyForm);
    }
  }

  return (
    <section className="panel" aria-labelledby="create-title">
      <div className="panel-heading">
        <h2 id="create-title">Create secret</h2>
      </div>
      <form onSubmit={(event) => void submit(event)}>
        <label>
          Path
          <input
            value={form.path}
            onChange={(event) => setForm({ ...form, path: event.target.value })}
            placeholder="secret/team/service"
            maxLength={200}
            spellCheck={false}
            required
          />
        </label>
        <label>
          Name
          <input
            value={form.name}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
            maxLength={100}
            required
          />
        </label>
        <label>
          Description
          <input
            value={form.description}
            onChange={(event) => setForm({ ...form, description: event.target.value })}
            maxLength={500}
          />
        </label>
        <label>
          Plaintext
          <textarea
            value={form.plaintext}
            onChange={(event) => setForm({ ...form, plaintext: event.target.value })}
            rows={4}
            spellCheck={false}
            required
          />
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={form.isDynamic}
            onChange={(event) => setForm({ ...form, isDynamic: event.target.checked })}
          />
          Issue a dynamic lease
        </label>
        {form.isDynamic ? (
          <div className="field">
            <label>
              Lease TTL (seconds)
              <input
                type="number"
                min="10"
                max="3600"
                step="1"
                value={form.ttlSeconds}
                onChange={(event) => setForm({ ...form, ttlSeconds: Number(event.target.value) })}
                aria-describedby="ttl-hint"
                required
              />
            </label>
            <small id="ttl-hint" className="field-help">
              Renewals can extend a lease up to 5 times this TTL.
            </small>
          </div>
        ) : null}
        <button type="submit" className="btn btn-primary" disabled={disabled}>
          Encrypt secret
        </button>
      </form>
    </section>
  );
}
