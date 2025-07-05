import React, { useState, useEffect } from 'react';
import { Lock, Eye, EyeOff, CheckCircle, AlertTriangle, Shield } from 'lucide-react';
import { authService } from '../services/authService';
import Swal from 'sweetalert2';

interface ResetPasswordProps {
  token: string;
  onSuccess: () => void;
}

const ResetPassword: React.FC<ResetPasswordProps> = ({ token, onSuccess }) => {
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [passwordStrength, setPasswordStrength] = useState(0);

  const checkPasswordStrength = (password: string) => {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    return strength;
  };

  useEffect(() => {
    setPasswordStrength(checkPasswordStrength(newPassword));
  }, [newPassword]);

  const getStrengthColor = (strength: number) => {
    if (strength < 2) return 'bg-red-500';
    if (strength < 4) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const getStrengthText = (strength: number) => {
    if (strength < 2) return 'Weak';
    if (strength < 4) return 'Medium';
    return 'Strong';
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (passwordStrength < 3) {
      setError('Password is too weak. Please use a stronger password.');
      return;
    }

    setIsLoading(true);

    try {
      const response = await authService.resetPassword(token, newPassword);
      
      if (response.success) {
        await Swal.fire({
          title: 'Password Reset Successful!',
          text: 'Your password has been updated successfully. You can now log in with your new password.',
          icon: 'success',
          timer: 3000,
          showConfirmButton: false,
          background: '#ffffff',
          customClass: {
            popup: 'rounded-2xl'
          }
        });
        onSuccess();
      }
    } catch (err: any) {
      console.error('Password reset failed:', err);
      setError(err.message || 'Password reset failed. The link may have expired.');
    } finally {
      setIsLoading(false);
    }
  };

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
          <div className="flex items-center justify-center mb-6">
            <Shield className="w-8 h-8 text-indigo-600 mr-3" />
            <h2 className="text-3xl font-bold text-gray-800">Reset Password</h2>
          </div>

          <p className="text-gray-600 mb-6 text-center">
            Create a new secure password for your Dr.Net admin account.
          </p>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="newPassword" className="block text-sm font-semibold text-gray-700 mb-2">
                New Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type={showNewPassword ? 'text' : 'password'}
                  id="newPassword"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password"
                  required
                  disabled={isLoading}
                  className="w-full pl-12 pr-12 py-4 border-2 border-gray-200 rounded-xl focus:outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100 transition-all duration-200 bg-gray-50/50 disabled:opacity-50 disabled:cursor-not-allowed"
                />
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  disabled={isLoading}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors disabled:opacity-50"
                >
                  {showNewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              
              {newPassword && (
                <div className="mt-2">
                  <div className="flex items-center justify-between text-xs text-gray-600 mb-1">
                    <span>Password Strength</span>
                    <span className={`font-semibold ${passwordStrength < 2 ? 'text-red-600' : passwordStrength < 4 ? 'text-yellow-600' : 'text-green-600'}`}>
                      {getStrengthText(passwordStrength)}
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div 
                      className={`h-2 rounded-full transition-all duration-300 ${getStrengthColor(passwordStrength)}`}
                      style={{ width: `${(passwordStrength / 5) * 100}%` }}
                    ></div>
                  </div>
                </div>
              )}
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-semibold text-gray-700 mb-2">
                Confirm New Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  id="confirmPassword"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                  required
                  disabled={isLoading}
                  className="w-full pl-12 pr-12 py-4 border-2 border-gray-200 rounded-xl focus:outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100 transition-all duration-200 bg-gray-50/50 disabled:opacity-50 disabled:cursor-not-allowed"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  disabled={isLoading}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors disabled:opacity-50"
                >
                  {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              
              {confirmPassword && newPassword !== confirmPassword && (
                <p className="text-red-600 text-xs mt-1 flex items-center">
                  <AlertTriangle className="w-3 h-3 mr-1" />
                  Passwords do not match
                </p>
              )}
              
              {confirmPassword && newPassword === confirmPassword && (
                <p className="text-green-600 text-xs mt-1 flex items-center">
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Passwords match
                </p>
              )}
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
              disabled={isLoading || !newPassword || !confirmPassword || newPassword !== confirmPassword || passwordStrength < 3}
              className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 text-white py-4 rounded-xl font-bold hover:from-indigo-700 hover:to-purple-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
            >
              {isLoading ? (
                <div className="flex items-center justify-center">
                  <div className="loading-spinner mr-3"></div>
                  Updating Password...
                </div>
              ) : (
                <div className="flex items-center justify-center">
                  <Shield className="w-5 h-5 mr-2" />
                  Update Password
                </div>
              )}
            </button>
          </form>

          <div className="mt-6 bg-blue-50/80 backdrop-blur-sm border border-blue-200 rounded-2xl p-4">
            <div className="text-blue-800">
              <p className="text-sm font-semibold mb-2">Password Requirements:</p>
              <ul className="text-xs text-blue-600 space-y-1">
                <li>• At least 8 characters long</li>
                <li>• Contains uppercase and lowercase letters</li>
                <li>• Contains at least one number</li>
                <li>• Contains at least one special character</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;