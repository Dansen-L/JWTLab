import { Routes, Route, Navigate } from 'react-router-dom'
import AppShell from './components/AppShell'
import ModulePage from './pages/ModulePage'
import HomePage from './pages/HomePage'

export default function App() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/index.html" element={<Navigate to="/" replace />} />
        <Route path="/modules/:moduleSlug" element={<ModulePage />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </AppShell>
  )
}

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-64 gap-4">
      <h1 className="font-display text-h2 text-text-primary">404</h1>
      <p className="text-text-muted">Module not found.</p>
      <a href="/" className="btn-primary">Back to Home</a>
    </div>
  )
}
