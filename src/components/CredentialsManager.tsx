import React, { useState, useEffect } from 'react';
import { User, Mail, Key, Eye, EyeOff, Save, RefreshCw, AlertTriangle, CheckCircle } from 'lucide-react';
import { authService } from '../services/authService';
import Swal from 'sweetalert2';

const CredentialsManager: React.FC = () => {
  const [currentCredentials, setCurrentCredentials] = useState({ username: '', email: '' });
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingCredentials, setIsLoadingCredentials] = useState(true);
  const [error, setError] = useState('');
  const [passwordStrength, setPasswordStrength] = useState(0);

  useEffect(() => {
    loadCurrentCredentials();
  }, []);

  useEffect(() => {
    setPasswordStrength(checkPasswordStrength(newPassword));
  }, [newPassword]);

  const loadCurrentCredentials = async () => {
    try {
      setIsLoadingCredentials(true);
      const credentials = await authService.getCurrentCredentials();
      setCurrentCredentials(credentials);
    } catch (err: any) {
      console.error('Failed to load credentials:', err);
      setError('Failed to load current credentials');
    } finally {
      setIsLoadingCredentials(false);
    }
  };

  const checkPasswordStrength = (password: string) => {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    return strength;
  };

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

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    if (passwordStrength < 3) {
      setError('Password is too weak. Please use a stronger password.');
      return;
    }

    setIsLoading(true);

    try {
      await authService.changePassword(currentPassword, newPassword);
      
      await Swal.fire({
        title: 'Password Updated!',
        text: 'Your password has been successfully changed.',
        icon: 'success',
        timer: 2000,
        showConfirmButton: false,
        background: '#ffffff',
        customClass: {
          popup: 'rounded-2xl'
        }
      });

      // Clear form
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      console.error('Password change failed:', err);
      setError(err.message || 'Failed to change password');
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoadingCredentials) {
    return (
      <div className="bg-white rounded-2xl shadow-lg p-6">
        <div className="flex items-center justify-center py-8">
          <RefreshCw className="w-6 h-6 text-indigo-600 animate-spin mr-3" />
          <span className="text-gray-600">Loading credentials...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-2xl shadow-lg p-6">
      <div className="flex items-center mb-6">
        <Key className="w-6 h-6 text-indigo-600 mr-3" />
        <h2 className="text-2xl font-bold text-gray-800">Account Credentials</h2>
      </div>

      {/* Current Credentials Display */}
      <div className="mb-8 p-4 bg-gray-50 rounded-xl">
        <h3 className="text-lg font-semibold text-gray-700 mb-4">Current Login Details</h3>
        <div className="space-y-3">
          <div className="flex items-center">
            <User className="w-5 h-5 text-gray-500 mr-3" />
            <div>
              <p className="text-sm text-gray-600">Username</p>
              <p className="font-semibold text-gray-800">{currentCredentials.username}</p>
            </div>
          </div>
          <div className="flex items-center">
            <Mail className="w-5 h-5 text-gray-500 mr-3" />
            <div>
              <p className="text-sm text-gray-600">Recovery Email</p>
              <p className="font-semibold text-gray-800">{currentCredentials.email}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Password Change Form */}
      <form onSubmit={handlePasswordChange} className="space-y-6">
        <h3 className="text-lg font-semibold text-gray-700">Change Password</h3>

        <div>
          <label htmlFor="currentPassword" className="block text-sm font-semibold text-gray-700 mb-2">
            Current Password
          </label>
          <div className="relative">
            <Key className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type={showCurrentPassword ? 'text' : 'password'}
              id="currentPassword"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Enter current password"
              required
              disabled={isLoading}
              className="w-full pl-12 pr-12 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            />
            <button
              type="button"
              onClick={() => setShowCurrentPassword(!showCurrentPassword)}
              disabled={isLoading}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors disabled:opacity-50"
            >
              {showCurrentPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>
        </div>

        <div>
          <label htmlFor="newPassword" className="block text-sm font-semibold text-gray-700 mb-2">
            New Password
          </label>
          <div className="relative">
            <Key className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type={showNewPassword ? 'text' : 'password'}
              id="newPassword"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Enter new password"
              required
              disabled={isLoading}
              className="w-full pl-12 pr-12 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
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
            <Key className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type={showConfirmPassword ? 'text' : 'password'}
              id="confirmPassword"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm new password"
              required
              disabled={isLoading}
              className="w-full pl-12 pr-12 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:border-indigo-500 focus:ring-4 focus:ring-indigo-100 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
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
          disabled={isLoading || !currentPassword || !newPassword || !confirmPassword || newPassword !== confirmPassword || passwordStrength < 3}
          className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 text-white py-3 rounded-xl font-semibold hover:from-indigo-700 hover:to-purple-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
        >
          {isLoading ? (
            <div className="flex items-center justify-center">
              <RefreshCw className="w-5 h-5 mr-2 animate-spin" />
              Updating Password...
            </div>
          ) : (
            <div className="flex items-center justify-center">
              <Save className="w-5 h-5 mr-2" />
              Update Password
            </div>
          )}
        </button>
      </form>

      <div className="mt-6 bg-blue-50/80 border border-blue-200 rounded-xl p-4">
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
  );
};

export default CredentialsManager;