import React, { useState } from 'react';
import { Lock, User, Eye, EyeOff, Shield, Wifi, AlertTriangle, KeyRound } from 'lucide-react';
import { authService } from '../services/authService';
import ForgotPassword from './ForgotPassword';
import ResetPassword from './ResetPassword';
import Swal from 'sweetalert2';

interface LoginProps {
  onLogin: () => void;
}

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [retryAfter, setRetryAfter] = useState<number | null>(null);
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [showResetPassword, setShowResetPassword] = useState(false);
  const [resetToken, setResetToken] = useState('');

  // Check for reset token in URL on component mount
  React.useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    if (token) {
      setResetToken(token);
      setShowResetPassword(true);
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    setRetryAfter(null);

    try {
      await authService.login(username, password);
      
      // Show success message
      await Swal.fire({
        title: 'Welcome Back!',
        text: 'Successfully logged into Dr.Net Admin Portal',
        icon: 'success',
        timer: 2000,
        showConfirmButton: false,
        background: '#ffffff',
        customClass: {
          popup: 'rounded-2xl'
        }
      });

      onLogin();
    } catch (err: any) {
      console.error('Login failed:', err);
      
      // Handle rate limiting
      if (err.message.includes('too many') || err.message.includes('locked')) {
        setRetryAfter(15); // Default 15 minutes
        setError('Too many failed login attempts. Account temporarily locked.');
      } else {
        setError(err.message || 'Login failed. Please check your credentials and try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleForgotPassword = () => {
    setShowForgotPassword(true);
  };

  const handleBackToLogin = () => {
    setShowForgotPassword(false);
    setShowResetPassword(false);
    setError('');
  };

  const handleResetSuccess = () => {
    setShowResetPassword(false);
    setResetToken('');
    setError('');
  };

  // Countdown timer for retry
  React.useEffect(() => {
    if (retryAfter && retryAfter > 0) {
      const timer = setTimeout(() => {
        setRetryAfter(retryAfter - 1);
      }, 60000); // Update every minute

      return () => clearTimeout(timer);
    } else if (retryAfter === 0) {
      setRetryAfter(null);
      setError('');
    }
  }, [retryAfter]);

  // Show forgot password component
  if (showForgotPassword) {
    return <ForgotPassword onBack={handleBackToLogin} />;
  }

  // Show reset password component
  if (showResetPassword) {
    return <ResetPassword token={resetToken} onSuccess={handleResetSuccess} />;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-pink-200 via-purple-200 to-indigo-200 p-4">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-white/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-indigo-300/20 rounded-full blur-3xl animate-pulse delay-1000"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-80 h-80 bg-purple-300/15 rounded-full blur-3xl animate-pulse delay-500"></div>
      </div>

      <div className="relative z-10 w-full max-w-md">
        {/* Company branding */}
        <div className="text-center mb-8 animate-fadeInUp">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-r from-indigo-600 to-purple-600 rounded-2xl shadow-lg mb-4">
            <Wifi className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent mb-2">
            Dr.Net Labs
          </h1>
          <p className="text-gray-600 font-medium">Network Management Portal</p>
        </div>

        {/* Login form */}
        <form onSubmit={handleSubmit} className="bg-white/90 backdrop-blur-xl p-8 rounded-3xl shadow-2xl border border-white/20">
          <div className="flex items-center justify-center mb-6">
            <Shield className="w-8 h-8 text-indigo-600 mr-3" />
            <h2 className="text-3xl font-bold text-gray-800">Admin Access</h2>
          </div>

          <div className="space-y-6">
            <div className="relative">
              <label htmlFor="username" className="block text-sm font-semibold text-gray-700 mb-2">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="text"
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter your username"
                  required
                  disabled={isLoading || !!retryAfter}
                  className="w-full pl-12 pr-4 py-4 border-2 border-gray-200 rounded-xl focus:outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100 transition-all duration-200 bg-gray-50/50 disabled:opacity-50 disabled:cursor-not-allowed"
                />
              </div>
            </div>

            <div className="relative">
              <label htmlFor="password" className="block text-sm font-semibold text-gray-700 mb-2">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  disabled={isLoading || !!retryAfter}
                  className="w-full pl-12 pr-12 py-4 border-2 border-gray-200 rounded-xl focus:outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100 transition-all duration-200 bg-gray-50/50 disabled:opacity-50 disabled:cursor-not-allowed"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={isLoading || !!retryAfter}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors disabled:opacity-50"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 rounded-xl p-4 animate-fadeInUp">
                <p className="text-red-600 text-sm font-medium flex items-center">
                  <AlertTriangle className="w-4 h-4 mr-2" />
                  {error}
                  {retryAfter && (
                    <span className="ml-2 text-xs">
                      (Try again in {retryAfter} minutes)
                    </span>
                  )}
                </p>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading || !!retryAfter}
              className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 text-white py-4 rounded-xl font-bold hover:from-indigo-700 hover:to-purple-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
            >
              {isLoading ? (
                <div className="flex items-center justify-center">
                  <div className="loading-spinner mr-3"></div>
                  Authenticating...
                </div>
              ) : retryAfter ? (
                <div className="flex items-center justify-center">
                  <Lock className="w-5 h-5 mr-2" />
                  Account Locked ({retryAfter}m)
                </div>
              ) : (
                <div className="flex items-center justify-center">
                  <Lock className="w-5 h-5 mr-2" />
                  Sign In
                </div>
              )}
            </button>

            {/* Forgot Password Link */}
            <div className="text-center">
              <button
                type="button"
                onClick={handleForgotPassword}
                disabled={isLoading || !!retryAfter}
                className="text-indigo-600 hover:text-indigo-800 text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center mx-auto"
              >
                <KeyRound className="w-4 h-4 mr-1" />
                Forgot Password?
              </button>
            </div>
          </div>

          <div className="mt-6 text-center">
            <p className="text-xs text-gray-500">
              🔒 Authorized personnel only. All access is monitored and logged.
            </p>
          </div>
        </form>

        {/* Security notice */}
        <div className="mt-6 bg-blue-50/80 backdrop-blur-sm border border-blue-200 rounded-2xl p-4">
          <div className="flex items-center text-blue-800">
            <Shield className="w-5 h-5 mr-2" />
            <div>
              <p className="text-sm font-semibold">Security Features Active</p>
              <p className="text-xs text-blue-600">
                • Rate limiting • JWT tokens • Encrypted passwords • Session monitoring
              </p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-8 text-gray-600">
          <p className="text-sm">
            © 2025 Dr.Net Technology Labs. All rights reserved.
          </p>
          <p className="text-xs mt-1">
            Secure Network Management Portal v2.0
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;