import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  PropsWithChildren,
  SelectHTMLAttributes,
} from 'react'
import clsx from 'clsx'

export function Card({
  className,
  children,
}: PropsWithChildren<{ className?: string }>) {
  return (
    <section
      className={clsx(
        'rounded-2xl border border-slate-700 bg-slate-900/85 p-5 shadow-[0_16px_40px_-22px_rgba(16,24,40,0.35)] backdrop-blur-sm',
        className,
      )}
    >
      {children}
    </section>
  )
}

export function SectionTitle({
  title,
  subtitle,
}: {
  title: string
  subtitle?: string
}) {
  return (
    <header className="mb-4">
      <h2 className="text-xl font-semibold tracking-tight text-white">{title}</h2>
      {subtitle ? <p className="mt-1 text-sm text-slate-400">{subtitle}</p> : null}
    </header>
  )
}

export function Button({
  className,
  variant = 'primary',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'danger'
}) {
  return (
    <button
      className={clsx(
        'inline-flex items-center justify-center rounded-xl px-4 py-2 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-50',
        variant === 'primary' &&
          'bg-[var(--profile-accent,var(--accent-primary,#0f766e))] text-white hover:brightness-110 active:brightness-95',
        variant === 'secondary' &&
          'border border-slate-600 bg-slate-900 text-slate-200 hover:bg-slate-800',
        variant === 'danger' &&
          'bg-rose-600 text-white hover:bg-rose-700 active:bg-rose-800',
        className,
      )}
      {...props}
    />
  )
}

export function Input({
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={clsx(
        'w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white outline-none ring-teal-500/30 transition focus:border-teal-600 focus:ring-4',
        className,
      )}
      {...props}
    />
  )
}

export function Select({
  className,
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={clsx(
        'w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white outline-none ring-teal-500/30 transition focus:border-teal-600 focus:ring-4',
        className,
      )}
      {...props}
    >
      {children}
    </select>
  )
}

export function Label({ children }: PropsWithChildren) {
  return <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-400">{children}</label>
}

export function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-800 py-2 last:border-0">
      <span>{label}</span>
      <strong className="max-w-[58%] truncate text-right text-white">{value}</strong>
    </div>
  )
}

export function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-800/70 p-3">
      <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
      <p className="mt-1 text-lg font-semibold text-white">{value}</p>
    </div>
  )
}

export function Notice({
  children,
  tone = 'info',
  className,
}: PropsWithChildren<{
  tone?: 'info' | 'warning' | 'danger' | 'success'
  className?: string
}>) {
  const styles = {
    info: 'border-sky-800 bg-sky-950 text-sky-300',
    warning: 'border-amber-800 bg-amber-950 text-amber-300',
    danger: 'border-rose-800 bg-rose-950 text-rose-300',
    success: 'border-emerald-800 bg-emerald-950 text-emerald-300',
  }

  return (
    <div className={clsx('rounded-xl border p-3 text-sm', styles[tone], className)}>{children}</div>
  )
}
