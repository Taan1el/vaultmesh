import { act, cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from '../test/axe';
import { createUpdateStore } from './offline';
import { UpdateNotice } from './UpdateNotice';

afterEach(cleanup);
describe('update notice', () => {
  it('stays hidden until a new version is waiting, then offers one Reload button', async () => {
    const store = createUpdateStore(); const apply = vi.fn(() => true);
    const { container } = render(<UpdateNotice store={store} apply={apply} />);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    act(() => store.set(true));
    expect(screen.getByRole('status')).toHaveTextContent('A new version is ready.');
    expect((await axe(container)).violations).toEqual([]);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Reload' }));
    expect(apply).toHaveBeenCalledOnce();
    act(() => store.set(false)); expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });
});
