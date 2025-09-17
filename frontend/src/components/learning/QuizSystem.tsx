import React, { useState, useEffect } from 'react';
import { CheckCircleIcon, XCircleIcon, ClockIcon, TrophyIcon } from '@heroicons/react/24/outline';

interface QuizQuestion {
  id: string;
  question: string;
  type: 'multiple-choice' | 'true-false' | 'code-analysis' | 'scenario';
  options?: string[];
  correctAnswer: string | number;
  explanation: string;
  difficulty: 'easy' | 'medium' | 'hard';
  category: string;
  code?: string;
  language?: string;
}

interface Quiz {
  id: string;
  title: string;
  description: string;
  category: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  timeLimit: number; // in minutes
  passingScore: number; // percentage
  questions: QuizQuestion[];
  prerequisites: string[];
}

interface QuizAttempt {
  quizId: string;
  startTime: Date;
  endTime?: Date;
  answers: { [questionId: string]: string | number };
  score?: number;
  passed?: boolean;
}

interface QuizSystemProps {
  userProgress: {
    totalModulesCompleted: number;
    totalQuizzesPassed: number;
    certificationsEarned: string[];
    currentStreak: number;
    totalTimeSpent: number;
    skillLevel: 'novice' | 'intermediate' | 'advanced' | 'expert';
  };
  onQuizComplete: (quizId: string, score: number) => void;
}

export const QuizSystem: React.FC<QuizSystemProps> = ({ userProgress, onQuizComplete }) => {
  const [selectedQuiz, setSelectedQuiz] = useState<Quiz | null>(null);
  const [currentAttempt, setCurrentAttempt] = useState<QuizAttempt | null>(null);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [timeRemaining, setTimeRemaining] = useState(0);
  const [showResults, setShowResults] = useState(false);
  const [quizHistory, setQuizHistory] = useState<QuizAttempt[]>([]);

  // Quiz database
  const quizzes: Quiz[] = [
    {
      id: 'sql-injection-basics',
      title: 'SQL Injection Fundamentals',
      description: 'Test your understanding of basic SQL injection concepts and prevention techniques',
      category: 'SQL Injection',
      difficulty: 'beginner',
      timeLimit: 15,
      passingScore: 80,
      prerequisites: [],
      questions: [
        {
          id: 'sql-1',
          question: 'What is SQL injection?',
          type: 'multiple-choice',
          options: [
            'A method to optimize database queries',
            'A technique to inject malicious SQL code into application queries',
            'A way to backup database data',
            'A database indexing strategy'
          ],
          correctAnswer: 1,
          explanation: 'SQL injection is a code injection technique that exploits security vulnerabilities in an application\'s database layer by inserting malicious SQL code.',
          difficulty: 'easy',
          category: 'SQL Injection'
        },
        {
          id: 'sql-2',
          question: 'Which of the following is a vulnerable SQL query?',
          type: 'code-analysis',
          code: `// Option A
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);

// Option B  
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);`,
          language: 'javascript',
          options: ['Option A', 'Option B', 'Both are vulnerable', 'Neither is vulnerable'],
          correctAnswer: 1,
          explanation: 'Option B is vulnerable because it uses string concatenation, allowing SQL injection. Option A uses parameterized queries which are safe.',
          difficulty: 'medium',
          category: 'SQL Injection'
        },
        {
          id: 'sql-3',
          question: 'What does the SQL comment sequence "--" do in an injection attack?',
          type: 'multiple-choice',
          options: [
            'It executes the query twice',
            'It comments out the rest of the SQL query',
            'It creates a new database connection',
            'It encrypts the query'
          ],
          correctAnswer: 1,
          explanation: 'The "--" sequence comments out the rest of the SQL query, allowing attackers to ignore parts of the original query like password checks.',
          difficulty: 'easy',
          category: 'SQL Injection'
        },
        {
          id: 'sql-4',
          question: 'A login form uses this query: SELECT * FROM users WHERE email = \'[INPUT]\' AND password = \'[PASSWORD]\'. What input would bypass authentication?',
          type: 'scenario',
          options: [
            'admin@example.com',
            'admin@example.com\' --',
            'admin@example.com\' OR \'1\'=\'1\' --',
            'Both B and C'
          ],
          correctAnswer: 3,
          explanation: 'Both options B and C would bypass authentication. Option B comments out the password check, while option C uses a condition that\'s always true.',
          difficulty: 'medium',
          category: 'SQL Injection'
        },
        {
          id: 'sql-5',
          question: 'Parameterized queries prevent SQL injection.',
          type: 'true-false',
          correctAnswer: 'true',
          explanation: 'True. Parameterized queries (prepared statements) separate SQL code from data, preventing malicious SQL from being executed.',
          difficulty: 'easy',
          category: 'SQL Injection'
        }
      ]
    },
    {
      id: 'xss-fundamentals',
      title: 'Cross-Site Scripting (XSS) Basics',
      description: 'Evaluate your knowledge of XSS vulnerabilities and prevention methods',
      category: 'XSS',
      difficulty: 'beginner',
      timeLimit: 20,
      passingScore: 75,
      prerequisites: [],
      questions: [
        {
          id: 'xss-1',
          question: 'What are the three main types of XSS?',
          type: 'multiple-choice',
          options: [
            'Reflected, Stored, DOM-based',
            'Client, Server, Database',
            'GET, POST, PUT',
            'Input, Output, Processing'
          ],
          correctAnswer: 0,
          explanation: 'The three main types of XSS are Reflected (non-persistent), Stored (persistent), and DOM-based XSS.',
          difficulty: 'easy',
          category: 'XSS'
        },
        {
          id: 'xss-2',
          question: 'Which React code is vulnerable to XSS?',
          type: 'code-analysis',
          code: `// Option A
<div>{userComment}</div>

// Option B
<div dangerouslySetInnerHTML={{__html: userComment}} />`,
          language: 'jsx',
          options: ['Option A', 'Option B', 'Both', 'Neither'],
          correctAnswer: 1,
          explanation: 'Option B is vulnerable because dangerouslySetInnerHTML renders raw HTML without sanitization. Option A automatically escapes content.',
          difficulty: 'medium',
          category: 'XSS'
        },
        {
          id: 'xss-3',
          question: 'What is the primary goal of XSS attacks?',
          type: 'multiple-choice',
          options: [
            'To crash the web server',
            'To execute malicious scripts in victim browsers',
            'To steal database passwords',
            'To perform SQL injection'
          ],
          correctAnswer: 1,
          explanation: 'XSS attacks aim to execute malicious JavaScript in victim browsers to steal data, hijack sessions, or perform actions on behalf of users.',
          difficulty: 'easy',
          category: 'XSS'
        },
        {
          id: 'xss-4',
          question: 'Content Security Policy (CSP) can help prevent XSS attacks.',
          type: 'true-false',
          correctAnswer: 'true',
          explanation: 'True. CSP helps prevent XSS by controlling which resources the browser is allowed to load and execute.',
          difficulty: 'medium',
          category: 'XSS'
        }
      ]
    },
    {
      id: 'idor-assessment',
      title: 'IDOR Vulnerability Assessment',
      description: 'Test your ability to identify and exploit Insecure Direct Object References',
      category: 'IDOR',
      difficulty: 'intermediate',
      timeLimit: 25,
      passingScore: 70,
      prerequisites: ['sql-injection-basics'],
      questions: [
        {
          id: 'idor-1',
          question: 'What does IDOR stand for?',
          type: 'multiple-choice',
          options: [
            'Insecure Direct Object Reference',
            'Internal Database Object Retrieval',
            'Invalid Data Object Request',
            'Indirect Database Operation Risk'
          ],
          correctAnswer: 0,
          explanation: 'IDOR stands for Insecure Direct Object Reference, a vulnerability where applications expose internal object references without proper authorization.',
          difficulty: 'easy',
          category: 'IDOR'
        },
        {
          id: 'idor-2',
          question: 'You notice a URL like /api/users/123/profile. How would you test for IDOR?',
          type: 'scenario',
          options: [
            'Change 123 to 124 and see if you can access another user\'s profile',
            'Add more parameters to the URL',
            'Change the HTTP method to POST',
            'Encode the URL'
          ],
          correctAnswer: 0,
          explanation: 'Testing IDOR involves changing object identifiers (like user IDs) to see if you can access resources belonging to other users.',
          difficulty: 'medium',
          category: 'IDOR'
        },
        {
          id: 'idor-3',
          question: 'Which code properly prevents IDOR?',
          type: 'code-analysis',
          code: `// Option A
app.get('/api/tasks/:id', (req, res) => {
  const task = db.getTask(req.params.id);
  res.json(task);
});

// Option B
app.get('/api/tasks/:id', authenticateUser, (req, res) => {
  const task = db.getTask(req.params.id);
  if (task.userId !== req.user.id) {
    return res.status(403).json({error: 'Forbidden'});
  }
  res.json(task);
});`,
          language: 'javascript',
          options: ['Option A', 'Option B', 'Both', 'Neither'],
          correctAnswer: 1,
          explanation: 'Option B prevents IDOR by checking if the authenticated user owns the requested resource before returning it.',
          difficulty: 'medium',
          category: 'IDOR'
        }
      ]
    },
    {
      id: 'session-security',
      title: 'Session Management Security',
      description: 'Assess your understanding of secure session management practices',
      category: 'Session Management',
      difficulty: 'intermediate',
      timeLimit: 20,
      passingScore: 75,
      prerequisites: [],
      questions: [
        {
          id: 'session-1',
          question: 'Where should JWT tokens be stored in a web application for maximum security?',
          type: 'multiple-choice',
          options: [
            'localStorage',
            'sessionStorage',
            'httpOnly cookies',
            'URL parameters'
          ],
          correctAnswer: 2,
          explanation: 'httpOnly cookies are the most secure storage method as they cannot be accessed by JavaScript, preventing XSS-based token theft.',
          difficulty: 'medium',
          category: 'Session Management'
        },
        {
          id: 'session-2',
          question: 'What is a major security risk of using weak JWT secrets?',
          type: 'multiple-choice',
          options: [
            'Slower application performance',
            'Tokens can be forged by attackers',
            'Increased server memory usage',
            'Database connection issues'
          ],
          correctAnswer: 1,
          explanation: 'Weak JWT secrets allow attackers to forge valid tokens, completely bypassing authentication.',
          difficulty: 'medium',
          category: 'Session Management'
        },
        {
          id: 'session-3',
          question: 'Session tokens should have expiration times.',
          type: 'true-false',
          correctAnswer: 'true',
          explanation: 'True. Session tokens should expire to limit the window of opportunity if a token is compromised.',
          difficulty: 'easy',
          category: 'Session Management'
        }
      ]
    },
    {
      id: 'comprehensive-security',
      title: 'Comprehensive Security Assessment',
      description: 'Advanced quiz covering multiple vulnerability types and security concepts',
      category: 'Comprehensive',
      difficulty: 'advanced',
      timeLimit: 45,
      passingScore: 85,
      prerequisites: ['sql-injection-basics', 'xss-fundamentals', 'idor-assessment'],
      questions: [
        {
          id: 'comp-1',
          question: 'Which vulnerability is most likely to lead to complete database compromise?',
          type: 'multiple-choice',
          options: [
            'Reflected XSS',
            'IDOR',
            'SQL Injection',
            'CSRF'
          ],
          correctAnswer: 2,
          explanation: 'SQL Injection can lead to complete database compromise as attackers can execute arbitrary SQL commands.',
          difficulty: 'medium',
          category: 'Comprehensive'
        },
        {
          id: 'comp-2',
          question: 'An application allows users to upload profile pictures by providing a URL. What security risks does this introduce?',
          type: 'scenario',
          options: [
            'SSRF (Server-Side Request Forgery)',
            'Potential access to internal services',
            'Local file inclusion if file:// URLs are allowed',
            'All of the above'
          ],
          correctAnswer: 3,
          explanation: 'URL-based file uploads can lead to SSRF attacks, internal service access, and local file inclusion vulnerabilities.',
          difficulty: 'hard',
          category: 'Comprehensive'
        },
        {
          id: 'comp-3',
          question: 'Defense in depth means relying on a single strong security control.',
          type: 'true-false',
          correctAnswer: 'false',
          explanation: 'False. Defense in depth involves implementing multiple layers of security controls to protect against various attack vectors.',
          difficulty: 'medium',
          category: 'Comprehensive'
        }
      ]
    }
  ];

  // Timer effect
  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    if (currentAttempt && timeRemaining > 0 && !showResults) {
      interval = setInterval(() => {
        setTimeRemaining(prev => {
          if (prev <= 1) {
            handleQuizSubmit();
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }
    
    return () => clearInterval(interval);
  }, [currentAttempt, timeRemaining, showResults]);

  // Load quiz history
  useEffect(() => {
    const savedHistory = localStorage.getItem('quizHistory');
    if (savedHistory) {
      setQuizHistory(JSON.parse(savedHistory));
    }
  }, []);

  const startQuiz = (quiz: Quiz) => {
    const attempt: QuizAttempt = {
      quizId: quiz.id,
      startTime: new Date(),
      answers: {}
    };
    
    setSelectedQuiz(quiz);
    setCurrentAttempt(attempt);
    setCurrentQuestionIndex(0);
    setTimeRemaining(quiz.timeLimit * 60); // Convert to seconds
    setShowResults(false);
  };

  const handleAnswer = (questionId: string, answer: string | number) => {
    if (!currentAttempt) return;
    
    setCurrentAttempt(prev => ({
      ...prev!,
      answers: {
        ...prev!.answers,
        [questionId]: answer
      }
    }));
  };

  const nextQuestion = () => {
    if (selectedQuiz && currentQuestionIndex < selectedQuiz.questions.length - 1) {
      setCurrentQuestionIndex(prev => prev + 1);
    } else {
      handleQuizSubmit();
    }
  };

  const previousQuestion = () => {
    if (currentQuestionIndex > 0) {
      setCurrentQuestionIndex(prev => prev - 1);
    }
  };

  const handleQuizSubmit = () => {
    if (!currentAttempt || !selectedQuiz) return;
    
    const endTime = new Date();
    let correctAnswers = 0;
    
    selectedQuiz.questions.forEach(question => {
      const userAnswer = currentAttempt.answers[question.id];
      if (userAnswer === question.correctAnswer || 
          (typeof question.correctAnswer === 'string' && 
           userAnswer?.toString().toLowerCase() === question.correctAnswer.toLowerCase())) {
        correctAnswers++;
      }
    });
    
    const score = Math.round((correctAnswers / selectedQuiz.questions.length) * 100);
    const passed = score >= selectedQuiz.passingScore;
    
    const completedAttempt: QuizAttempt = {
      ...currentAttempt,
      endTime,
      score,
      passed
    };
    
    // Save to history
    const updatedHistory = [...quizHistory, completedAttempt];
    setQuizHistory(updatedHistory);
    localStorage.setItem('quizHistory', JSON.stringify(updatedHistory));
    
    // Update current attempt
    setCurrentAttempt(completedAttempt);
    setShowResults(true);
    
    // Notify parent component
    onQuizComplete(selectedQuiz.id, score);
  };

  const resetQuiz = () => {
    setSelectedQuiz(null);
    setCurrentAttempt(null);
    setCurrentQuestionIndex(0);
    setTimeRemaining(0);
    setShowResults(false);
  };

  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'text-green-600 bg-green-100';
      case 'intermediate': return 'text-yellow-600 bg-yellow-100';
      case 'advanced': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const isQuizAvailable = (quiz: Quiz) => {
    return quiz.prerequisites.every(prereqId => 
      quizHistory.some(attempt => attempt.quizId === prereqId && attempt.passed)
    );
  };

  const getQuizAttempts = (quizId: string) => {
    return quizHistory.filter(attempt => attempt.quizId === quizId);
  };

  const getBestScore = (quizId: string) => {
    const attempts = getQuizAttempts(quizId);
    return attempts.length > 0 ? Math.max(...attempts.map(a => a.score || 0)) : 0;
  };

  // Quiz Results View
  if (showResults && currentAttempt && selectedQuiz) {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="bg-white rounded-lg shadow-lg p-8">
          <div className="text-center mb-8">
            <div className={`inline-flex items-center justify-center w-16 h-16 rounded-full mb-4 ${
              currentAttempt.passed ? 'bg-green-100' : 'bg-red-100'
            }`}>
              {currentAttempt.passed ? (
                <CheckCircleIcon className="h-8 w-8 text-green-600" />
              ) : (
                <XCircleIcon className="h-8 w-8 text-red-600" />
              )}
            </div>
            <h2 className="text-2xl font-bold text-gray-900 mb-2">
              {currentAttempt.passed ? 'Congratulations!' : 'Keep Learning!'}
            </h2>
            <p className="text-gray-600">
              You scored {currentAttempt.score}% on {selectedQuiz.title}
            </p>
            <p className="text-sm text-gray-500 mt-1">
              Passing score: {selectedQuiz.passingScore}%
            </p>
          </div>

          {/* Score Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="text-center">
              <div className="text-3xl font-bold text-blue-600">{currentAttempt.score}%</div>
              <div className="text-sm text-gray-600">Final Score</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-green-600">
                {Object.keys(currentAttempt.answers).length}
              </div>
              <div className="text-sm text-gray-600">Questions Answered</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-purple-600">
                {currentAttempt.endTime && currentAttempt.startTime ? 
                  Math.round((currentAttempt.endTime.getTime() - currentAttempt.startTime.getTime()) / 1000 / 60) : 0}
              </div>
              <div className="text-sm text-gray-600">Minutes Taken</div>
            </div>
          </div>

          {/* Question Review */}
          <div className="space-y-6 mb-8">
            <h3 className="text-lg font-semibold text-gray-900">Question Review</h3>
            {selectedQuiz.questions.map((question, index) => {
              const userAnswer = currentAttempt.answers[question.id];
              const isCorrect = userAnswer === question.correctAnswer || 
                (typeof question.correctAnswer === 'string' && 
                 userAnswer?.toString().toLowerCase() === question.correctAnswer.toLowerCase());
              
              return (
                <div key={question.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-start space-x-3">
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center text-sm font-medium ${
                      isCorrect ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                    }`}>
                      {isCorrect ? '✓' : '✗'}
                    </div>
                    <div className="flex-1">
                      <h4 className="font-medium text-gray-900 mb-2">
                        Question {index + 1}: {question.question}
                      </h4>
                      
                      {question.code && (
                        <pre className="bg-gray-100 p-3 rounded text-sm mb-3 overflow-x-auto">
                          <code>{question.code}</code>
                        </pre>
                      )}
                      
                      <div className="text-sm space-y-1">
                        <div>
                          <span className="font-medium">Your answer:</span>{' '}
                          <span className={isCorrect ? 'text-green-600' : 'text-red-600'}>
                            {question.options ? question.options[userAnswer as number] : userAnswer?.toString()}
                          </span>
                        </div>
                        {!isCorrect && (
                          <div>
                            <span className="font-medium">Correct answer:</span>{' '}
                            <span className="text-green-600">
                              {question.options ? 
                                question.options[question.correctAnswer as number] : 
                                question.correctAnswer.toString()}
                            </span>
                          </div>
                        )}
                        <div className="text-gray-600 mt-2">
                          <span className="font-medium">Explanation:</span> {question.explanation}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Actions */}
          <div className="flex justify-center space-x-4">
            <button
              onClick={() => startQuiz(selectedQuiz)}
              className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 transition-colors"
            >
              Retake Quiz
            </button>
            <button
              onClick={resetQuiz}
              className="bg-gray-200 text-gray-700 px-6 py-2 rounded-md hover:bg-gray-300 transition-colors"
            >
              Back to Quizzes
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Quiz Taking View
  if (selectedQuiz && currentAttempt && !showResults) {
    const currentQuestion = selectedQuiz.questions[currentQuestionIndex];
    const userAnswer = currentAttempt.answers[currentQuestion.id];
    
    return (
      <div className="max-w-4xl mx-auto">
        <div className="bg-white rounded-lg shadow-lg p-8">
          {/* Quiz Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-xl font-semibold text-gray-900">{selectedQuiz.title}</h2>
              <p className="text-sm text-gray-600">
                Question {currentQuestionIndex + 1} of {selectedQuiz.questions.length}
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <div className={`flex items-center space-x-2 ${timeRemaining < 300 ? 'text-red-600' : 'text-gray-600'}`}>
                <ClockIcon className="h-5 w-5" />
                <span className="font-mono">{formatTime(timeRemaining)}</span>
              </div>
              <button
                onClick={resetQuiz}
                className="text-gray-500 hover:text-gray-700"
              >
                Exit Quiz
              </button>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="mb-8">
            <div className="bg-gray-200 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${((currentQuestionIndex + 1) / selectedQuiz.questions.length) * 100}%` }}
              />
            </div>
          </div>

          {/* Question */}
          <div className="mb-8">
            <h3 className="text-lg font-medium text-gray-900 mb-4">
              {currentQuestion.question}
            </h3>
            
            {currentQuestion.code && (
              <pre className="bg-gray-100 p-4 rounded-lg text-sm mb-6 overflow-x-auto">
                <code>{currentQuestion.code}</code>
              </pre>
            )}

            {/* Answer Options */}
            <div className="space-y-3">
              {currentQuestion.type === 'multiple-choice' || currentQuestion.type === 'code-analysis' || currentQuestion.type === 'scenario' ? (
                currentQuestion.options?.map((option, index) => (
                  <label
                    key={index}
                    className={`flex items-center p-4 border rounded-lg cursor-pointer transition-colors ${
                      userAnswer === index ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:bg-gray-50'
                    }`}
                  >
                    <input
                      type="radio"
                      name={currentQuestion.id}
                      value={index}
                      checked={userAnswer === index}
                      onChange={() => handleAnswer(currentQuestion.id, index)}
                      className="mr-3"
                    />
                    <span>{option}</span>
                  </label>
                ))
              ) : currentQuestion.type === 'true-false' ? (
                ['True', 'False'].map((option) => (
                  <label
                    key={option}
                    className={`flex items-center p-4 border rounded-lg cursor-pointer transition-colors ${
                      userAnswer === option.toLowerCase() ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:bg-gray-50'
                    }`}
                  >
                    <input
                      type="radio"
                      name={currentQuestion.id}
                      value={option.toLowerCase()}
                      checked={userAnswer === option.toLowerCase()}
                      onChange={() => handleAnswer(currentQuestion.id, option.toLowerCase())}
                      className="mr-3"
                    />
                    <span>{option}</span>
                  </label>
                ))
              ) : null}
            </div>
          </div>

          {/* Navigation */}
          <div className="flex justify-between">
            <button
              onClick={previousQuestion}
              disabled={currentQuestionIndex === 0}
              className={`px-4 py-2 rounded-md ${
                currentQuestionIndex === 0
                  ? 'text-gray-400 cursor-not-allowed'
                  : 'text-gray-700 hover:bg-gray-100'
              }`}
            >
              Previous
            </button>

            <button
              onClick={nextQuestion}
              disabled={userAnswer === undefined}
              className={`px-6 py-2 rounded-md ${
                userAnswer === undefined
                  ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              {currentQuestionIndex === selectedQuiz.questions.length - 1 ? 'Submit Quiz' : 'Next Question'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Quiz Selection View
  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Knowledge Quizzes</h2>
        <p className="text-gray-600">
          Test your understanding of web application security concepts
        </p>
      </div>

      {/* Quiz Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {quizzes.map((quiz) => {
          const isAvailable = isQuizAvailable(quiz);
          const attempts = getQuizAttempts(quiz.id);
          const bestScore = getBestScore(quiz.id);
          const hasPassed = attempts.some(attempt => attempt.passed);
          
          return (
            <div
              key={quiz.id}
              className={`border rounded-lg p-6 ${
                !isAvailable ? 'opacity-50 bg-gray-50' : 'bg-white hover:shadow-md'
              } transition-shadow`}
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">{quiz.title}</h3>
                  <p className="text-sm text-gray-600 mb-3">{quiz.description}</p>
                  
                  <div className="flex items-center space-x-4 text-sm">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getDifficultyColor(quiz.difficulty)}`}>
                      {quiz.difficulty}
                    </span>
                    <span className="text-gray-500 flex items-center">
                      <ClockIcon className="h-4 w-4 mr-1" />
                      {quiz.timeLimit} min
                    </span>
                    <span className="text-gray-500">
                      {quiz.questions.length} questions
                    </span>
                  </div>
                </div>
                
                {hasPassed && (
                  <div className="flex items-center text-green-600">
                    <TrophyIcon className="h-5 w-5 mr-1" />
                    <span className="text-sm font-medium">{bestScore}%</span>
                  </div>
                )}
              </div>

              {attempts.length > 0 && (
                <div className="mb-4 text-sm text-gray-600">
                  <div>Attempts: {attempts.length}</div>
                  <div>Best Score: {bestScore}%</div>
                  <div>Status: {hasPassed ? 'Passed' : 'Not Passed'}</div>
                </div>
              )}

              {quiz.prerequisites.length > 0 && (
                <div className="mb-4 text-xs text-gray-500">
                  Prerequisites: {quiz.prerequisites.join(', ')}
                </div>
              )}

              <button
                onClick={() => startQuiz(quiz)}
                disabled={!isAvailable}
                className={`w-full py-2 px-4 rounded-md text-sm font-medium ${
                  !isAvailable
                    ? 'bg-gray-200 text-gray-500 cursor-not-allowed'
                    : 'bg-blue-600 text-white hover:bg-blue-700'
                } transition-colors`}
              >
                {attempts.length > 0 ? 'Retake Quiz' : 'Start Quiz'}
              </button>
            </div>
          );
        })}
      </div>

      {/* Quiz History */}
      {quizHistory.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Quiz Attempts</h3>
          <div className="space-y-3">
            {quizHistory.slice(-5).reverse().map((attempt, index) => {
              const quiz = quizzes.find(q => q.id === attempt.quizId);
              if (!quiz) return null;
              
              return (
                <div key={index} className="flex items-center justify-between p-3 border border-gray-200 rounded">
                  <div>
                    <div className="font-medium text-gray-900">{quiz.title}</div>
                    <div className="text-sm text-gray-600">
                      {attempt.startTime ? new Date(attempt.startTime).toLocaleDateString() : 'Unknown date'}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`font-medium ${attempt.passed ? 'text-green-600' : 'text-red-600'}`}>
                      {attempt.score}%
                    </div>
                    <div className="text-sm text-gray-600">
                      {attempt.passed ? 'Passed' : 'Failed'}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}