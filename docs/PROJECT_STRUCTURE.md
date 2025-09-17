# Project Structure

This document outlines the complete directory structure of the Vulnerable Web Application project.

```
vulnerable-webapp/
├── README.md                          # Main project documentation
├── package.json                       # Root package.json with workspace scripts
├── docker-compose.yml                 # Docker services configuration
├── setup.sh                          # Unix setup script
├── setup.bat                         # Windows setup script
├── .gitignore                         # Git ignore patterns
│
├── frontend/                          # React.js frontend application
│   ├── package.json                  # Frontend dependencies and scripts
│   ├── vite.config.ts                # Vite configuration
│   ├── tsconfig.json                 # TypeScript configuration
│   ├── tsconfig.node.json            # Node-specific TypeScript config
│   ├── tailwind.config.js            # Tailwind CSS configuration
│   ├── postcss.config.js             # PostCSS configuration
│   ├── .eslintrc.cjs                 # ESLint configuration
│   ├── .prettierrc                   # Prettier configuration
│   ├── index.html                    # Main HTML template
│   ├── Dockerfile                    # Frontend Docker configuration
│   └── src/                          # Frontend source code
│       ├── main.tsx                  # Application entry point
│       ├── App.tsx                   # Main App component
│       ├── index.css                 # Global styles with Tailwind
│       ├── types/
│       │   └── index.ts              # TypeScript type definitions
│       └── store/
│           └── store.ts              # Redux store configuration
│
├── backend/                           # Node.js Express backend API
│   ├── package.json                  # Backend dependencies and scripts
│   ├── tsconfig.json                 # TypeScript configuration
│   ├── .eslintrc.js                  # ESLint configuration
│   ├── .prettierrc                   # Prettier configuration
│   ├── .env.example                  # Environment variables template
│   ├── nodemon.json                  # Nodemon configuration
│   ├── Dockerfile                    # Backend Docker configuration
│   ├── uploads/                      # File upload directory (vulnerable)
│   │   └── .gitkeep                  # Keep directory in git
│   ├── prisma/                       # Prisma ORM configuration
│   │   ├── schema.prisma             # Database schema definition
│   │   └── migrations/               # Database migration files
│   │       └── .gitkeep              # Keep directory in git
│   └── src/                          # Backend source code
│       ├── server.ts                 # Express server entry point
│       ├── seed.ts                   # Database seeding script
│       └── types/
│           └── index.ts              # TypeScript type definitions
│
├── database/                          # Database initialization
│   └── init/                         # Database initialization scripts
│       └── 01-init.sql               # PostgreSQL initialization
│
└── docs/                             # Documentation
    └── PROJECT_STRUCTURE.md          # This file
```

## Key Components

### Frontend (`/frontend`)
- **React.js 18+** with TypeScript for type safety
- **Vite** for fast development builds and hot module replacement
- **Tailwind CSS** for utility-first styling with custom design system
- **Redux Toolkit** for state management
- **React Router** for client-side routing
- **Axios** for HTTP client with authentication interceptors

### Backend (`/backend`)
- **Node.js** with **Express.js** framework
- **TypeScript** for type safety and better development experience
- **Prisma ORM** for type-safe database operations
- **JWT** for authentication (intentionally vulnerable)
- **bcryptjs** for password hashing
- **Multer** for file uploads (vulnerable to path traversal)

### Database
- **PostgreSQL 14+** as the primary database
- **Docker containerization** for consistent development environment
- **Prisma migrations** for schema versioning
- **Seed data** for demo users and tasks

### Development Tools
- **ESLint** and **Prettier** for code quality and formatting
- **Docker Compose** for orchestrating services
- **Nodemon** for backend hot reloading
- **Concurrently** for running multiple development servers

## Security Vulnerabilities (Intentional)

The application includes the following intentional vulnerabilities for educational purposes:

1. **SQL Injection (CWE-89)** - Raw SQL queries without parameterization
2. **Cross-Site Scripting (XSS) (CWE-79)** - Unsafe HTML rendering
3. **Insecure Direct Object References (IDOR) (CWE-639)** - Missing authorization checks
4. **Insecure Session Management (CWE-384)** - Weak JWT implementation
5. **Server-Side Request Forgery (SSRF) (CWE-918)** - Unvalidated URL requests
6. **Local File Inclusion (LFI) (CWE-22)** - Path traversal vulnerabilities

## Getting Started

1. **Prerequisites**: Node.js 18+, Docker, Docker Compose
2. **Setup**: Run `./setup.sh` (Unix) or `setup.bat` (Windows)
3. **Development**: Run `npm run dev` to start both frontend and backend
4. **Access**: Frontend at http://localhost:3000, API at http://localhost:3001

## Environment Configuration

### Backend Environment Variables (`.env`)
```
DATABASE_URL="postgresql://webapp_user:webapp_password@localhost:5432/vulnerable_webapp"
JWT_SECRET="weak-secret-key-for-education"
JWT_EXPIRES_IN="30d"
PORT=3001
NODE_ENV=development
CORS_ORIGIN="http://localhost:3000"
```

### Docker Services
- **PostgreSQL**: Port 5432, database `vulnerable_webapp`
- **Backend**: Port 3001, Node.js API server
- **Frontend**: Port 3000, React development server

## Development Workflow

1. **Database Changes**: Update `prisma/schema.prisma` → Run `npm run db:migrate`
2. **Frontend Changes**: Edit files in `frontend/src/` → Hot reload automatically
3. **Backend Changes**: Edit files in `backend/src/` → Nodemon restarts server
4. **Styling**: Use Tailwind classes → PostCSS processes automatically

## Security Warning

⚠️ **This application contains intentional security vulnerabilities for educational purposes only. Never deploy this application in a production environment or on public networks.**