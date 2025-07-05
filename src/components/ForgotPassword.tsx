import React, { useState } from 'react';
import { ArrowLeft, Mail, Send, CheckCircle, AlertTriangle } from 'lucide-react';
import { authService } from '../services/authService';
import Swal from 'sweetalert2';

interface ForgotPasswordProps {
  onBack: () => void;
}

const ForgotPassword: React.FC<ForgotPasswordProps> = ({ onBack }) => {
  const [username, setUsername] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const response = await authService.forgotPassword(username);
      
      if (response.success) {
        setIsSuccess(true);
        await Swal.fire({
          title: 'Reset Email Sent!',
          text: 'Password reset instructions have been sent to ojwangjuli5@gmail.com',
          icon: 'success',
          timer: 3000,
          showConfirmButton: false,
          background: '#ffffff',
          customClass: {
            popup: 'rounded-2xl'
          }
        });
      }
    } catch (err: any) {
      console.error('Forgot password failed:', err);
      setError(err.message || 'Failed to send reset email. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  if (isSuccess) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-pink-200 via-purple-200 to-indigo-200 p-4">
        <div className="relative z-10 w-full max-w-md">
          <div className="bg-white/90 backdrop-blur-xl p-8 rounded-3xl shadow-2xl border border-white/20 text-center">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-green-100 rounded-full mb-6">
              <CheckCircle className="w-8 h-8 text-green-600" />
            </div>
            
            <h2 className="text-2xl font-bold text-gray-800 mb-4">Email Sent Successfully!</h2>
            
            <p className="text-gray-600 mb-6">
              Password reset instructions have been sent to:
              <br />
              <span className="font-semibold text-indigo-600">ojwangjuli5@gmail.com</span>
            </p>
            
            <p className="text-sm text-gray-500 mb-8">
              Please check your email and follow the instructions to reset your password. 
              The reset link will expire in 1 hour for security reasons.
            </p>
            
            <button
              onClick={onBack}
              className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 text-white py-3 rounded-xl font-semibold hover:from-indigo-700 hover:to-purple-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105"
            >
              Back to Login
            </button>
          </div>
        </div>
      </div>
    );
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
        <div className="bg-white/90 backdrop-blur-xl p-8 rounded-3xl shadow-2xl border border-white/20">
          <div className="flex items-center mb-6">
            <button
              onClick={onBack}
              className="mr-4 p-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div className="flex items-center">
              <Mail className="w-6 h-6 text-indigo-600 mr-3" />
              <h2 className="text-2xl font-bold text-gray-800">Reset Password</h2>
            </div>
          </div>

          <p className="text-gray-600 mb-6">
            Enter your username and we'll send password reset instructions to the registered email address.
          </p>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="username" className="block text-sm font-semibold text-gray-700 mb-2">
                Username
              </label>
              <input
                type="text"
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
                disabled={isLoading}
                className="w-full px-4 py-4 border-2 border-gray-200 rounded-xl focus:outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100 transition-all duration-200 bg-gray-50/50 disabled:opacity-50 disabled:cursor-not-allowed"
              />
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 rounded-xl p-4">
                <p className="text-red-600 text-sm font-medium flex items-center">
                  <AlertTriangle className="w-4 h-4 mr-2" />
                  {error}
                </p>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading || !username.trim()}
              className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 text-white py-4 rounded-xl font-bold hover:from-indigo-700 hover:to-purple-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
            >
              {isLoading ? (
                <div className="flex items-center justify-center">
                  <div className="loading-spinner mr-3"></div>
                  Sending Reset Email...
                </div>
              ) : (
                <div className="flex items-center justify-center">
                  <Send className="w-5 h-5 mr-2" />
                  Send Reset Email
                </div>
              )}
            </button>
          </form>

          <div className="mt-6 bg-blue-50/80 backdrop-blur-sm border border-blue-200 rounded-2xl p-4">
            <div className="flex items-start text-blue-800">
              <Mail className="w-5 h-5 mr-2 mt-0.5" />
              <div>
                <p className="text-sm font-semibold">Email will be sent to:</p>
                <p className="text-sm text-blue-600">ojwangjuli5@gmail.com</p>
                <p className="text-xs text-blue-600 mt-1">
                  Reset link expires in 1 hour for security
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;