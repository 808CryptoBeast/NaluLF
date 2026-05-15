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
        'rounded-2xl border border-slate-200 bg-white/85 p-5 shadow-[0_16px_40px_-22px_rgba(16,24,40,0.35)] backdrop-blur-sm',
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
      <h2 className="text-xl font-semibold tracking-tight text-slate-900">{title}</h2>
      {subtitle ? <p className="mt-1 text-sm text-slate-600">{subtitle}</p> : null}
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
          'bg-teal-700 text-white hover:bg-teal-800 active:bg-teal-900',
        variant === 'secondary' &&
          'border border-slate-300 bg-white text-slate-800 hover:bg-slate-100',
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
        'w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 outline-none ring-teal-500/30 transition focus:border-teal-600 focus:ring-4',
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
        'w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 outline-none ring-teal-500/30 transition focus:border-teal-600 focus:ring-4',
        className,
      )}
      {...props}
    >
      {children}
    </select>
  )
}

export function Label({ children }: PropsWithChildren) {
  return <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">{children}</label>
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
    info: 'border-sky-200 bg-sky-50 text-sky-800',
    warning: 'border-amber-200 bg-amber-50 text-amber-800',
    danger: 'border-rose-200 bg-rose-50 text-rose-700',
    success: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  }

  return (
    <div className={clsx('rounded-xl border p-3 text-sm', styles[tone], className)}>{children}</div>
  )
}
