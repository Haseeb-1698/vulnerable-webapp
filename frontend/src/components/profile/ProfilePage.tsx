import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { api } from '../../utils/api';
import { User } from '../../types';
import AvatarUpload from './AvatarUpload';
import TaskImport from './TaskImport';
import FileBrowser from './FileBrowser';

const ProfilePage: React.FC = () => {
  const { user, updateUser } = useAuth();
  const [profile, setProfile] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: ''
  });

  useEffect(() => {
    fetchProfile();
  }, []);

  useEffect(() => {
    if (profile) {
      setFormData({
        firstName: profile.firstName,
        lastName: profile.lastName
      });
    }
  }, [profile]);

  const fetchProfile = async () => {
    try {
      setLoading(true);
      const response = await api.get('/users/profile');
      console.log('Profile API Response:', response);
      console.log('Profile Response data:', response.data);
      
      // Handle different response structures
      const profileData = response.data || response;
      console.log('Profile data:', profileData);
      setProfile(profileData);
      setError(null);
    } catch (err: any) {
      console.error('Profile error:', err);
      setError(err.response?.data?.error || 'Failed to load profile');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await api.put('/users/profile', formData);
      // Handle different response structures
      const profileData = response.data || response;
      setProfile(profileData);
      updateUser(response.data);
      setIsEditing(false);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to update profile');
    }
  };

  const handleAvatarUpdate = (avatarUrl: string) => {
    if (profile) {
      const updatedProfile = { ...profile, avatarUrl };
      setProfile(updatedProfile);
      updateUser(updatedProfile);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Profile Not Found</h2>
          <p className="text-gray-600">Unable to load your profile information.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 bg-grid-slate bg-ornaments py-8">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-white shadow-lg rounded-xl border border-slate-200">
          {/* Profile Header */}
          <div className="px-6 py-8 border-b border-slate-200 bg-gradient-to-r from-white to-slate-50">
            <div className="flex items-center space-x-6">
              <div className="flex-shrink-0">
                {profile.avatarUrl ? (
                  <img
                    className="h-24 w-24 rounded-full object-cover border-2 border-slate-200"
                    src={profile.avatarUrl}
                    alt={`${profile.firstName} ${profile.lastName}`}
                    onError={(e) => {
                      const target = e.target as HTMLImageElement;
                      target.src = `https://ui-avatars.com/api/?name=${encodeURIComponent(profile.firstName + ' ' + profile.lastName)}&background=3b82f6&color=fff`;
                    }}
                  />
                ) : (
                  <div className="h-24 w-24 rounded-full bg-blue-600 flex items-center justify-center text-white text-3xl font-bold">
                    {profile.firstName.charAt(0)}{profile.lastName.charAt(0)}
                  </div>
                )}
              </div>
              <div className="flex-1">
                <h1 className="text-3xl font-bold text-slate-900">
                  {profile.firstName} {profile.lastName}
                </h1>
                <p className="text-slate-600">{profile.email}</p>
                <p className="text-sm text-slate-500">
                  Member since {new Date(profile.createdAt).toLocaleDateString()}
                </p>
                {profile.emailVerified ? (
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 mt-2">
                    ✓ Email Verified
                  </span>
                ) : (
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 mt-2">
                    ⚠ Email Not Verified
                  </span>
                )}
              </div>
              <div>
                <button
                  onClick={() => setIsEditing(!isEditing)}
                  className="btn-primary"
                >
                  {isEditing ? 'Cancel' : 'Edit Profile'}
                </button>
              </div>
            </div>
          </div>

          {error && (
            <div className="px-6 py-4 bg-red-50 border-l-4 border-red-400">
              <p className="text-red-700">{error}</p>
            </div>
          )}

          {/* Profile Edit Form */}
          {isEditing && (
            <div className="px-6 py-6 border-b border-slate-200">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Edit Profile Information</h3>
              <form onSubmit={handleUpdateProfile} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="firstName" className="block text-sm font-medium text-gray-700">
                      First Name
                    </label>
                    <input
                      type="text"
                      id="firstName"
                      value={formData.firstName}
                      onChange={(e) => setFormData({ ...formData, firstName: e.target.value })}
                      className="input"
                      required
                    />
                  </div>
                  <div>
                    <label htmlFor="lastName" className="block text-sm font-medium text-gray-700">
                      Last Name
                    </label>
                    <input
                      type="text"
                      id="lastName"
                      value={formData.lastName}
                      onChange={(e) => setFormData({ ...formData, lastName: e.target.value })}
                      className="input"
                      required
                    />
                  </div>
                </div>
                <div className="flex space-x-3">
                  <button
                    type="submit"
                    className="btn-primary"
                  >
                    Save Changes
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsEditing(false)}
                    className="btn-secondary"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* Profile Sections */}
          <div className="px-6 py-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {/* Avatar Upload Section */}
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-4">Profile Picture</h3>
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
                  <div className="flex">
                    <div className="flex-shrink-0">
                      <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                    </div>
                    <div className="ml-3">
                      <h4 className="text-sm font-medium text-yellow-800">Security Warning</h4>
                      <p className="text-sm text-yellow-700 mt-1">
                        This avatar upload feature contains intentional security vulnerabilities for educational purposes. 
                        It demonstrates SSRF (Server-Side Request Forgery) and LFI (Local File Inclusion) attacks.
                      </p>
                    </div>
                  </div>
                </div>
                <AvatarUpload onAvatarUpdate={handleAvatarUpdate} />
              </div>

              {/* Task Import Section */}
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-4">Task Import</h3>
                <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
                  <div className="flex">
                    <div className="flex-shrink-0">
                      <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                      </svg>
                    </div>
                    <div className="ml-3">
                      <h4 className="text-sm font-medium text-red-800">Critical Vulnerability</h4>
                      <p className="text-sm text-red-700 mt-1">
                        This task import feature is extremely vulnerable to SSRF attacks. It can access cloud metadata services, 
                        internal network resources, and local files. Use only for security testing!
                      </p>
                    </div>
                  </div>
                </div>
                <TaskImport />
              </div>
            </div>

            {/* File Browser Section */}
            <div className="mt-8">
              <h3 className="text-lg font-medium text-gray-900 mb-4">File Browser</h3>
              <div className="bg-orange-50 border border-orange-200 rounded-lg p-4 mb-4">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <svg className="h-5 w-5 text-orange-400" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <div className="ml-3">
                    <h4 className="text-sm font-medium text-orange-800">Path Traversal Vulnerability</h4>
                    <p className="text-sm text-orange-700 mt-1">
                      This file browser demonstrates path traversal vulnerabilities. It allows access to files outside 
                      the intended directory through directory traversal attacks.
                    </p>
                  </div>
                </div>
              </div>
              <FileBrowser />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;