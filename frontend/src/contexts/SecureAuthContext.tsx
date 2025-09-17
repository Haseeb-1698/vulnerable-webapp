import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { api } from '../utils/api';

/**
 * Secure Authentication Context
 * 
 * This context provides secure authentication state management with:
 * 1. HttpOnly cookie-based token storage
 * 2. Automatic token refresh mechanism
 * 3. Secure logout and session management
 * 4. Proper error handling and security measures
 */

interface User {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  emailVerified: boolean;
  createdAt?: string;
  updatedAt?: string;
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  sessionInfo: {
    sessionId?: string;
    expiresAt?: Date;
  } | null;
}

type AuthAction =
  | { type: 'AUTH_START' }
  | { type: 'AUTH_SUCCESS'; payload: { user: User; sessionInfo?: any } }
  | { type: 'AUTH_FAILURE'; payload: string }
  | { type: 'AUTH_LOGOUT' }
  | { type: 'AUTH_REFRESH_SUCCESS'; payload: { expiresAt?: Date } }
  | { type: 'CLEAR_ERROR' };

const initialState: AuthState = {
  user: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
  sessionInfo: null
};

const authReducer = (state: AuthState, action: AuthAction): AuthState => {
  switch (action.type) {
    case 'AUTH_START':
      return {
        ...state,
        isLoading: true,
        error: null
      };
    
    case 'AUTH_SUCCESS':
      return {
        ...state,
        user: action.payload.user,
        isAuthenticated: true,
        isLoading: false,
        error: null,
        sessionInfo: action.payload.sessionInfo || null
      };
    
    case 'AUTH_FAILURE':
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: action.payload,
        sessionInfo: null
      };
    
    case 'AUTH_LOGOUT':
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
        sessionInfo: null
      };
    
    case 'AUTH_REFRESH_SUCCESS':
      return {
        ...state,
        sessionInfo: {
          ...state.sessionInfo,
          expiresAt: action.payload.expiresAt
        }
      };
    
    case 'CLEAR_ERROR':
      return {
        ...state,
        error: null
      };
    
    default:
      return state;
  }
};

interface AuthContextType extends AuthState {
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
  register: (userData: {
    email: string;
    password: string;
    confirmPassword: string;
    firstName: string;
    lastName: string;
  }) => Promise<void>;
  logout: () => Promise<void>;
  logoutAll: () => Promise<void>;
  refreshToken: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string, confirmPassword: string) => Promise<void>;
  clearError: () => void;
  checkAuthStatus: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useSecureAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useSecureAuth must be used within a SecureAuthProvider');
  }
  return context;
};

interface SecureAuthProviderProps {
  children: React.ReactNode;
}

export const SecureAuthProvider: React.FC<SecureAuthProviderProps> = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Check authentication status on mount
  useEffect(() => {
    checkAuthStatus();
  }, []);

  // Set up automatic token refresh
  useEffect(() => {
    if (state.isAuthenticated && state.sessionInfo?.expiresAt) {
      const expiresAt = new Date(state.sessionInfo.expiresAt);
      const now = new Date();
      const timeUntilExpiry = expiresAt.getTime() - now.getTime();
      
      // Refresh token 2 minutes before expiry
      const refreshTime = Math.max(timeUntilExpiry - 2 * 60 * 1000, 60 * 1000);
      
      const refreshTimer = setTimeout(() => {
        refreshToken();
      }, refreshTime);
      
      return () => clearTimeout(refreshTimer);
    }
  }, [state.sessionInfo?.expiresAt, state.isAuthenticated]);

  const checkAuthStatus = async (): Promise<void> => {
    try {
      dispatch({ type: 'AUTH_START' });
      
      // Try to get current user (this will use httpOnly cookies)
      const response = await api.get('/secure-auth/me');
      
      dispatch({
        type: 'AUTH_SUCCESS',
        payload: {
          user: response.data.user
        }
      });
    } catch (error: any) {
      // If authentication fails, try to refresh token
      try {
        await refreshToken();
      } catch (refreshError) {
        dispatch({
          type: 'AUTH_FAILURE',
          payload: 'Authentication expired'
        });
      }
    }
  };

  const login = async (email: string, password: string, rememberMe: boolean = false): Promise<void> => {
    try {
      dispatch({ type: 'AUTH_START' });
      
      const response = await api.post('/secure-auth/login', {
        email,
        password,
        rememberMe
      });
      
      dispatch({
        type: 'AUTH_SUCCESS',
        payload: {
          user: response.data.user,
          sessionInfo: response.data.session
        }
      });
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || 'Login failed';
      dispatch({
        type: 'AUTH_FAILURE',
        payload: errorMessage
      });
      throw new Error(errorMessage);
    }
  };

  const register = async (userData: {
    email: string;
    password: string;
    confirmPassword: string;
    firstName: string;
    lastName: string;
  }): Promise<void> => {
    try {
      dispatch({ type: 'AUTH_START' });
      
      const response = await api.post('/secure-auth/register', userData);
      
      // Registration successful, but user needs to verify email
      dispatch({
        type: 'AUTH_FAILURE',
        payload: response.data.nextStep || 'Please verify your email address'
      });
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || 'Registration failed';
      dispatch({
        type: 'AUTH_FAILURE',
        payload: errorMessage
      });
      throw new Error(errorMessage);
    }
  };

  const logout = async (): Promise<void> => {
    try {
      await api.post('/secure-auth/logout');
    } catch (error) {
      // Even if logout request fails, clear local state
      console.error('Logout request failed:', error);
    } finally {
      dispatch({ type: 'AUTH_LOGOUT' });
      // Refresh the page to ensure clean state
      window.location.reload();
    }
  };

  const logoutAll = async (): Promise<void> => {
    try {
      await api.post('/secure-auth/logout-all');
    } catch (error) {
      console.error('Logout all request failed:', error);
    } finally {
      dispatch({ type: 'AUTH_LOGOUT' });
      // Refresh the page to ensure clean state
      window.location.reload();
    }
  };

  const refreshToken = async (): Promise<void> => {
    try {
      const response = await api.post('/secure-auth/refresh');
      
      dispatch({
        type: 'AUTH_REFRESH_SUCCESS',
        payload: {
          expiresAt: response.data.expiresAt ? new Date(response.data.expiresAt) : undefined
        }
      });
    } catch (error: any) {
      // If refresh fails, user needs to login again
      dispatch({
        type: 'AUTH_FAILURE',
        payload: 'Session expired. Please login again.'
      });
      throw error;
    }
  };

  const changePassword = async (
    currentPassword: string,
    newPassword: string,
    confirmPassword: string
  ): Promise<void> => {
    try {
      await api.post('/secure-auth/change-password', {
        currentPassword,
        newPassword,
        confirmPassword
      });
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || 'Password change failed';
      throw new Error(errorMessage);
    }
  };

  const clearError = (): void => {
    dispatch({ type: 'CLEAR_ERROR' });
  };

  const contextValue: AuthContextType = {
    ...state,
    login,
    register,
    logout,
    logoutAll,
    refreshToken,
    changePassword,
    clearError,
    checkAuthStatus
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

export default SecureAuthProvider;