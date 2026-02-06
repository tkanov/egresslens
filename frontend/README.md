# EgressLens Frontend

React + TypeScript frontend for EgressLens network egress monitoring tool.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start development server:
```bash
npm run dev
```

The frontend will run on `http://localhost:5173`.

## Project Structure

- `src/pages/` - Page components (UploadPage, ReportPage)
- `src/components/` - Reusable components (KPICards, TopDestinations, TimelineChart, FlagsPanel)
- `src/components/ui/` - shadcn/ui components
- `src/lib/` - Utilities (utils.ts for cn helper)
- `src/api.ts` - API client functions

## Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool and dev server
- **Tailwind CSS** - Styling
- **shadcn/ui** - UI component library
- **React Router** - Routing
- **Recharts** - Chart library

## Development

The frontend connects to the FastAPI backend running on `http://localhost:8000`. Make sure the backend is running before starting the frontend.

## Building

```bash
npm run build
```

This creates a production build in the `dist/` directory.
