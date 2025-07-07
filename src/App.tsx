import React, { useState, useEffect } from 'react';
import { Monitor, Users, Settings, LogOut, FileText, Download, Calendar, DollarSign } from 'lucide-react';
import Login from './components/Login';
import CredentialsManager from './components/CredentialsManager';
import { authService } from './services/authService';
import Swal from 'sweetalert2';

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const isValid = await authService.verifyToken();
      setIsAuthenticated(isValid);
    } catch (error) {
      console.error('Auth check failed:', error);
      setIsAuthenticated(false);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = () => {
    setIsAuthenticated(true);
    setActiveTab('dashboard');
  };

  const handleLogout = async () => {
    const result = await Swal.fire({
      title: 'Confirm Logout',
      text: 'Are you sure you want to log out?',
      icon: 'question',
      showCancelButton: true,
      confirmButtonColor: '#dc2626',
      cancelButtonColor: '#6b7280',
      confirmButtonText: 'Yes, logout',
      cancelButtonText: 'Cancel'
    });

    if (result.isConfirmed) {
      await authService.logout();
      setIsAuthenticated(false);
      setActiveTab('dashboard');
      
      await Swal.fire({
        title: 'Logged Out',
        text: 'You have been successfully logged out.',
        icon: 'success',
        timer: 2000,
        showConfirmButton: false
      });
    }
  };

  const generatePaymentReceipt = () => {
    // Create receipt data
    const receiptData = {
      receiptNumber: `RCP-${Date.now()}`,
      date: new Date().toLocaleDateString(),
      time: new Date().toLocaleTimeString(),
      amount: '$99.00',
      service: 'Dr.Net Admin Portal - Monthly Subscription',
      paymentMethod: 'Credit Card ****1234',
      status: 'Paid'
    };

    // Generate PDF content as HTML
    const receiptHTML = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Payment Receipt</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          .header { text-align: center; border-bottom: 2px solid #4f46e5; padding-bottom: 20px; margin-bottom: 30px; }
          .company-name { font-size: 24px; font-weight: bold; color: #4f46e5; }
          .receipt-title { font-size: 18px; margin-top: 10px; }
          .receipt-info { margin: 20px 0; }
          .info-row { display: flex; justify-content: space-between; margin: 10px 0; padding: 8px 0; border-bottom: 1px solid #e5e7eb; }
          .label { font-weight: bold; }
          .amount { font-size: 20px; font-weight: bold; color: #059669; }
          .footer { margin-top: 40px; text-align: center; color: #6b7280; font-size: 12px; }
          .status-paid { color: #059669; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="header">
          <div class="company-name">Dr.Net Technology Labs</div>
          <div class="receipt-title">Payment Receipt</div>
        </div>
        
        <div class="receipt-info">
          <div class="info-row">
            <span class="label">Receipt Number:</span>
            <span>${receiptData.receiptNumber}</span>
          </div>
          <div class="info-row">
            <span class="label">Date:</span>
            <span>${receiptData.date}</span>
          </div>
          <div class="info-row">
            <span class="label">Time:</span>
            <span>${receiptData.time}</span>
          </div>
          <div class="info-row">
            <span class="label">Service:</span>
            <span>${receiptData.service}</span>
          </div>
          <div class="info-row">
            <span class="label">Payment Method:</span>
            <span>${receiptData.paymentMethod}</span>
          </div>
          <div class="info-row">
            <span class="label">Amount:</span>
            <span class="amount">${receiptData.amount}</span>
          </div>
          <div class="info-row">
            <span class="label">Status:</span>
            <span class="status-paid">${receiptData.status}</span>
          </div>
        </div>
        
        <div class="footer">
          <p>Thank you for your business!</p>
          <p>Dr.Net Technology Labs - Network Management Solutions</p>
          <p>Contact: ojwangjuli5@gmail.com</p>
        </div>
      </body>
      </html>
    `;

    // Create and download PDF
    const blob = new Blob([receiptHTML], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `DrNet-Receipt-${receiptData.receiptNumber}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    Swal.fire({
      title: 'Receipt Generated!',
      text: 'Your payment receipt has been downloaded.',
      icon: 'success',
      timer: 2000,
      showConfirmButton: false
    });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-pink-200 via-purple-200 to-indigo-200">
        <div className="text-center">
          <div className="loading-spinner mb-4"></div>
          <p className="text-gray-600">Loading Dr.Net Admin Portal...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation Header */}
      <nav className="bg-white shadow-lg border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <Monitor className="w-8 h-8 text-indigo-600 mr-3" />
              <h1 className="text-xl font-bold text-gray-800">Dr.Net Admin Portal</h1>
            </div>
            
            <div className="flex items-center space-x-4">
              <button
                onClick={generatePaymentReceipt}
                className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
              >
                <Download className="w-4 h-4 mr-2" />
                Download Receipt
              </button>
              
              <button
                onClick={handleLogout}
                className="flex items-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
              >
                <LogOut className="w-4 h-4 mr-2" />
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="flex">
        {/* Sidebar */}
        <div className="w-64 bg-white shadow-lg h-screen">
          <div className="p-6">
            <nav className="space-y-2">
              <button
                onClick={() => setActiveTab('dashboard')}
                className={`w-full flex items-center px-4 py-3 rounded-lg transition-colors ${
                  activeTab === 'dashboard'
                    ? 'bg-indigo-100 text-indigo-700 border-l-4 border-indigo-500'
                    : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                <Monitor className="w-5 h-5 mr-3" />
                Dashboard
              </button>
              
              <button
                onClick={() => setActiveTab('users')}
                className={`w-full flex items-center px-4 py-3 rounded-lg transition-colors ${
                  activeTab === 'users'
                    ? 'bg-indigo-100 text-indigo-700 border-l-4 border-indigo-500'
                    : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                <Users className="w-5 h-5 mr-3" />
                User Management
              </button>
              
              <button
                onClick={() => setActiveTab('settings')}
                className={`w-full flex items-center px-4 py-3 rounded-lg transition-colors ${
                  activeTab === 'settings'
                    ? 'bg-indigo-100 text-indigo-700 border-l-4 border-indigo-500'
                    : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                <Settings className="w-5 h-5 mr-3" />
                Account Settings
              </button>

              <button
                onClick={() => setActiveTab('billing')}
                className={`w-full flex items-center px-4 py-3 rounded-lg transition-colors ${
                  activeTab === 'billing'
                    ? 'bg-indigo-100 text-indigo-700 border-l-4 border-indigo-500'
                    : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                <DollarSign className="w-5 h-5 mr-3" />
                Billing & Receipts
              </button>
            </nav>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 p-8">
          {activeTab === 'dashboard' && (
            <div>
              <h2 className="text-3xl font-bold text-gray-800 mb-8">Network Dashboard</h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div className="bg-white p-6 rounded-2xl shadow-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-600">Active Connections</p>
                      <p className="text-2xl font-bold text-green-600">1,247</p>
                    </div>
                    <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                      <Users className="w-6 h-6 text-green-600" />
                    </div>
                  </div>
                </div>
                
                <div className="bg-white p-6 rounded-2xl shadow-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-600">Network Uptime</p>
                      <p className="text-2xl font-bold text-blue-600">99.9%</p>
                    </div>
                    <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                      <Monitor className="w-6 h-6 text-blue-600" />
                    </div>
                  </div>
                </div>
                
                <div className="bg-white p-6 rounded-2xl shadow-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-600">Data Transfer</p>
                      <p className="text-2xl font-bold text-purple-600">2.4 TB</p>
                    </div>
                    <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center">
                      <FileText className="w-6 h-6 text-purple-600" />
                    </div>
                  </div>
                </div>
                
                <div className="bg-white p-6 rounded-2xl shadow-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-600">System Status</p>
                      <p className="text-2xl font-bold text-green-600">Healthy</p>
                    </div>
                    <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                      <Settings className="w-6 h-6 text-green-600" />
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white rounded-2xl shadow-lg p-6">
                <h3 className="text-xl font-bold text-gray-800 mb-4">Recent Activity</h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                    <div>
                      <p className="font-semibold text-gray-800">Network Maintenance Completed</p>
                      <p className="text-sm text-gray-600">System optimization and security updates</p>
                    </div>
                    <span className="text-sm text-gray-500">2 hours ago</span>
                  </div>
                  
                  <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                    <div>
                      <p className="font-semibold text-gray-800">New User Registration</p>
                      <p className="text-sm text-gray-600">45 new users joined the network</p>
                    </div>
                    <span className="text-sm text-gray-500">5 hours ago</span>
                  </div>
                  
                  <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                    <div>
                      <p className="font-semibold text-gray-800">Security Scan Completed</p>
                      <p className="text-sm text-gray-600">No threats detected, all systems secure</p>
                    </div>
                    <span className="text-sm text-gray-500">1 day ago</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'users' && (
            <div>
              <h2 className="text-3xl font-bold text-gray-800 mb-8">User Management</h2>
              
              <div className="bg-white rounded-2xl shadow-lg p-6">
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-xl font-bold text-gray-800">Active Users</h3>
                  <button className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors">
                    Add New User
                  </button>
                </div>
                
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200">
                        <th className="text-left py-3 px-4 font-semibold text-gray-700">Username</th>
                        <th className="text-left py-3 px-4 font-semibold text-gray-700">Email</th>
                        <th className="text-left py-3 px-4 font-semibold text-gray-700">Role</th>
                        <th className="text-left py-3 px-4 font-semibold text-gray-700">Status</th>
                        <th className="text-left py-3 px-4 font-semibold text-gray-700">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr className="border-b border-gray-100">
                        <td className="py-3 px-4">julius</td>
                        <td className="py-3 px-4">ojwangjuli5@gmail.com</td>
                        <td className="py-3 px-4">
                          <span className="bg-red-100 text-red-800 px-2 py-1 rounded-full text-xs font-semibold">
                            Admin
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs font-semibold">
                            Active
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <button className="text-indigo-600 hover:text-indigo-800 text-sm font-semibold">
                            Edit
                          </button>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'settings' && (
            <div>
              <h2 className="text-3xl font-bold text-gray-800 mb-8">Account Settings</h2>
              <CredentialsManager />
            </div>
          )}

          {activeTab === 'billing' && (
            <div>
              <h2 className="text-3xl font-bold text-gray-800 mb-8">Billing & Receipts</h2>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-white rounded-2xl shadow-lg p-6">
                  <h3 className="text-xl font-bold text-gray-800 mb-4">Current Subscription</h3>
                  <div className="space-y-4">
                    <div className="flex justify-between">
                      <span className="text-gray-600">Plan:</span>
                      <span className="font-semibold">Dr.Net Admin Portal Pro</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Monthly Cost:</span>
                      <span className="font-semibold text-green-600">$99.00</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Next Billing:</span>
                      <span className="font-semibold">{new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Status:</span>
                      <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs font-semibold">
                        Active
                      </span>
                    </div>
                  </div>
                </div>

                <div className="bg-white rounded-2xl shadow-lg p-6">
                  <h3 className="text-xl font-bold text-gray-800 mb-4">Payment Receipt</h3>
                  <p className="text-gray-600 mb-4">
                    Generate and download payment receipts for your records.
                  </p>
                  <button
                    onClick={generatePaymentReceipt}
                    className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 text-white py-3 rounded-xl font-semibold hover:from-indigo-700 hover:to-purple-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105"
                  >
                    <div className="flex items-center justify-center">
                      <Download className="w-5 h-5 mr-2" />
                      Generate Receipt PDF
                    </div>
                  </button>
                </div>
              </div>

              <div className="mt-8 bg-white rounded-2xl shadow-lg p-6">
                <h3 className="text-xl font-bold text-gray-800 mb-4">Payment History</h3>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200">
                        <th className="text-left py-3 px-4 font-semibold text-gray-700">Date</th>
                        <th className="text-left py-3 px-4 font-semibold text-gray-700">Description</th>
                        <th className="text-left py-3 px-4 font-semibold text-gray-700">Amount</th>
                        <th className="text-left py-3 px-4 font-semibold text-gray-700">Status</th>
                        <th className="text-left py-3 px-4 font-semibold text-gray-700">Receipt</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr className="border-b border-gray-100">
                        <td className="py-3 px-4">{new Date().toLocaleDateString()}</td>
                        <td className="py-3 px-4">Monthly Subscription</td>
                        <td className="py-3 px-4 font-semibold text-green-600">$99.00</td>
                        <td className="py-3 px-4">
                          <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs font-semibold">
                            Paid
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <button
                            onClick={generatePaymentReceipt}
                            className="text-indigo-600 hover:text-indigo-800 text-sm font-semibold flex items-center"
                          >
                            <Download className="w-4 h-4 mr-1" />
                            Download
                          </button>
                        </td>
                      </tr>
                      <tr className="border-b border-gray-100">
                        <td className="py-3 px-4">{new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toLocaleDateString()}</td>
                        <td className="py-3 px-4">Monthly Subscription</td>
                        <td className="py-3 px-4 font-semibold text-green-600">$99.00</td>
                        <td className="py-3 px-4">
                          <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs font-semibold">
                            Paid
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <button
                            onClick={generatePaymentReceipt}
                            className="text-indigo-600 hover:text-indigo-800 text-sm font-semibold flex items-center"
                          >
                            <Download className="w-4 h-4 mr-1" />
                            Download
                          </button>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default App;