# Implementation Plan

- [x] 1. Set up project foundation and development environment





  - Create project directory structure with frontend, backend, and database folders
  - Initialize React.js frontend with TypeScript, Vite, and Tailwind CSS
  - Set up Node.js/Express backend with TypeScript configuration
  - Configure PostgreSQL database with Docker Compose
  - Set up Prisma ORM with initial schema and migrations
  - Configure ESLint, Prettier, and development scripts
  - _Requirements: 1.1, 1.4, 1.5_

- [x] 2. Implement core authentication system with intentional vulnerabilities




  - [x] 2.1 Create user registration and login API endpoints

    - Build user registration endpoint with email validation
    - Implement login endpoint with JWT token generation using weak secrets
    - Create password hashing with bcrypt
    - Set up basic input validation with express-validator
    - _Requirements: 2.1, 2.2, 6.2_

  - [x] 2.2 Build vulnerable JWT session management




    - Implement JWT token generation with weak secret and long expiration
    - Create token storage in localStorage instead of httpOnly cookies
    - Build authentication middleware with inconsistent authorization checks
    - Implement logout functionality without proper token invalidation
    - _Requirements: 2.3, 6.2, 6.3_

  - [x] 2.3 Create React authentication components
















    - Build Login and Register components with form validation
    - Implement AuthProvider context for state management
    - Create protected route wrapper component
    - Set up token storage and retrieval in localStorage
    - _Requirements: 2.1, 2.4_

- [x] 3. Build task management system with IDOR vulnerabilities




  - [x] 3.1 Create task data models and database schema



    - Define Task and Comment models in Prisma schema
    - Set up database relationships between User, Task, and Comment
    - Create database migrations for task management tables
    - Implement enum types for task priority and status
    - _Requirements: 3.2, 3.3_

  - [x] 3.2 Implement vulnerable task CRUD API endpoints



    - Create task creation endpoint with proper validation
    - Build task retrieval endpoint without ownership verification (IDOR vulnerability)
    - Implement task update endpoint allowing unauthorized modifications
    - Create task deletion endpoint with missing authorization checks
    - Build task listing endpoint with potential data exposure
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 6.4_


  - [x] 3.3 Build React task management components


    - Create TaskList component with filtering and sorting
    - Implement TaskCard component for individual task display
    - Build TaskForm component for creating and editing tasks
    - Create TaskDetail component with comment functionality
    - Implement search functionality in frontend
    - _Requirements: 3.1, 3.5, 3.6_

- [-] 4. Implement SQL injection vulnerability in search functionality




  - [x] 4.1 Create vulnerable search endpoint



    - Build task search API endpoint using raw SQL queries with string concatenation
    - Implement database query execution without parameterization
    - Create error handling that exposes database structure information
    - Add logging that reveals SQL query details
    - _Requirements: 4.1, 4.2, 4.4_

  - [x] 4.2 Build search interface components








    - Create SearchBar component with real-time search
    - Implement search results display with task information
    - Build advanced search filters for task properties
    - Create search history functionality
    - _Requirements: 3.6, 4.3_

-

- [x] 5. Implement XSS vulnerability in comment system







  - [x] 5.1 Create comment data model and API endpoints



    - Add Comment model to Prisma schema with task relationships
    - Build comment creation endpoint without input sanitization
    - Implement comment retrieval endpoint exposing raw HTML content
    - Create comment deletion endpoint with authorization flaws
    - _Requirements: 5.1, 5.4_

  - [x] 5.2 Build vulnerable comment display components



    - Create CommentSection component using dangerouslySetInnerHTML
    - Implement CommentForm component allowing rich text input
    - Build comment rendering without HTML sanitization
    - Create comment editing functionality with XSS persistence
    - _Requirements: 5.1, 5.2, 5.3_

- [x] 6. Implement SSRF and LFI vulnerabilities in profile system




  - [x] 6.1 Create profile picture upload functionality


    - Add avatarUrl field to User model in database schema
    - Build avatar upload endpoint with URL fetching capability
    - Implement file serving endpoint with path traversal vulnerability
    - Create image processing without URL validation
    - _Requirements: Advanced SSRF requirement_

  - [x] 6.2 Build task import system with SSRF vulnerability


    - Create task import endpoint accepting external URLs
    - Implement HTTP request functionality without URL restrictions
    - Build cloud metadata access capability for AWS/GCP exploitation
    - Create internal network scanning functionality
    - Add local file inclusion through file:// protocol support
    - _Requirements: Advanced SSRF requirement_

  - [x] 6.3 Create profile management components


    - Build ProfilePage component with avatar upload
    - Implement AvatarUpload component with URL input
    - Create TaskImport component for external data sources
    - Build file browser component for uploaded files
    - _Requirements: Advanced SSRF requirement_

- [x] 7. Build interactive vulnerability management system




  - [x] 7.1 Create Security Lab dashboard infrastructure


    - Build VulnerabilityManager class for dynamic code switching
    - Implement hot-reload system for endpoint replacement
    - Create vulnerability configuration management
    - Build real-time code injection system
    - _Requirements: Interactive vulnerability system_

  - [x] 7.2 Implement individual vulnerability lab components


    - Create SQLInjectionLab component with code comparison
    - Build XSSLab component with payload testing
    - Implement IDORLab component with authorization testing
    - Create SessionManagementLab component with token analysis
    - Build SSRFLFILab component with network request testing
    - _Requirements: Interactive vulnerability system_

  - [x] 7.3 Build live attack testing system


    - Create LiveAttackTester component for payload execution
    - Implement real-time results display with success/failure indicators
    - Build payload library with pre-configured attack vectors
    - Create attack history and logging functionality
    - _Requirements: Interactive vulnerability system_


  - [x] 7.4 Create vulnerability toggle and code switching system

    - Implement toggle switches for each vulnerability type
    - Build code block display with syntax highlighting
    - Create side-by-side comparison view for vulnerable vs secure code
    - Implement real-time endpoint reloading without app restart
    - _Requirements: Interactive vulnerability system_

- [x] 8. Implement secure code alternatives and mitigation examples





  - [x] 8.1 Create secure SQL query implementations


    - Build parameterized query examples using Prisma ORM
    - Implement proper input validation and sanitization
    - Create safe error handling without information disclosure
    - Add query result limiting and access control
    - _Requirements: 8.1, 8.3_

  - [x] 8.2 Implement XSS prevention mechanisms


    - Create HTML sanitization using DOMPurify library
    - Build Content Security Policy (CSP) header implementation
    - Implement proper output encoding for user content
    - Create safe React component alternatives
    - _Requirements: 8.1, 8.3_

  - [x] 8.3 Build proper authorization and session management


    - Implement secure JWT token handling with strong secrets
    - Create httpOnly cookie-based session storage
    - Build proper ownership verification for all resources
    - Implement token refresh mechanism and secure logout
    - _Requirements: 8.1, 8.3_

  - [x] 8.4 Create SSRF and file upload security measures


    - Implement URL validation and domain whitelisting
    - Build private IP range blocking for SSRF prevention
    - Create secure file upload with type validation
    - Implement path traversal prevention in file serving
    - _Requirements: 8.1, 8.3_

- [x] 9. Build comprehensive testing and exploitation framework




  - [x] 9.1 Create automated vulnerability testing suite


    - Build Jest test cases for SQL injection exploitation
    - Implement XSS payload testing with DOM manipulation
    - Create IDOR testing with multiple user contexts
    - Build SSRF testing with internal network requests
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 9.2 Implement penetration testing integration


    - Create OWASP ZAP integration for automated scanning
    - Build SQLMap testing configuration and scripts
    - Implement Burp Suite integration for manual testing
    - Create custom exploitation scripts for each vulnerability
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 9.3 Build security assessment and reporting system


    - Create vulnerability assessment report generation
    - Implement CVSS scoring for identified vulnerabilities
    - Build exploitation evidence capture and documentation
    - Create before/after security comparison reports
    - _Requirements: 8.1, 8.2, 8.4, 8.5_

- [x] 10. Create educational documentation and learning materials









  - [x] 10.1 Build comprehensive vulnerability explanations




    - Create detailed documentation for each vulnerability type
    - Implement step-by-step exploitation tutorials
    - Build attack vector explanation with real-world examples
    - Create impact assessment and business risk documentation
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

  - [x] 10.2 Implement interactive learning features






    - Create guided tutorials for each vulnerability lab
    - Build progress tracking for learning objectives
    - Implement quiz system for knowledge verification
    - Create certification system for completed modules
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

- [x] 11. Set up production deployment and security hardening



  - [x] 11.1 Create Docker containerization for all services


    - Build multi-stage Dockerfile for frontend and backend
    - Create Docker Compose configuration for full stack
    - Implement environment variable management
    - Set up container security scanning and hardening
    - _Requirements: 1.4, 10.4_


  - [x] 11.2 Implement monitoring and logging systems

    - Create application logging for security events
    - Build attack detection and alerting system
    - Implement performance monitoring for concurrent users
    - Create audit trail for vulnerability toggle actions
    - _Requirements: 10.1, 10.2_

- [ ] 12. Final integration and testing
  - [ ] 12.1 Perform end-to-end vulnerability testing
    - Execute complete penetration testing workflow
    - Verify all vulnerabilities are exploitable as designed
    - Test vulnerability toggle system functionality
    - Validate secure code implementations prevent attacks
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [ ] 12.2 Create final documentation and deployment guide
    - Build complete setup and installation documentation
    - Create user guide for security lab functionality
    - Implement troubleshooting guide for common issues
    - Create educator guide for classroom usage
    - _Requirements: 8.4, 8.5, 9.1, 9.2, 9.3, 9.4, 9.5_