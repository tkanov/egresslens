import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { UploadPage } from '@/pages/UploadPage'
import { ReportPage } from '@/pages/ReportPage'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<UploadPage />} />
        <Route path="/reports/:id" element={<ReportPage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
