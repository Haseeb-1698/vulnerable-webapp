import React, { useState } from 'react';
import { api } from '../../utils/api';
import { AvatarUploadRequest, AvatarUploadResponse } from '../../types';

interface AvatarUploadProps {
  onAvatarUpdate: (avatarUrl: string) => void;
}

const AvatarUpload: React.FC<AvatarUploadProps> = ({ onAvatarUpdate }) => {
  const [imageUrl, setImageUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<AvatarUploadResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!imageUrl.trim()) return;

    setLoading(true);
    setError(null);
    setResponse(null);

    try {
      const requestData: AvatarUploadRequest = {
        imageUrl: imageUrl.trim(),
        fetchFromUrl: true
      };

      const result = await api.post('/users/avatar', requestData);
      setResponse(result.data);

      if (result.data.success && result.data.avatarUrl) {
        onAvatarUpdate(result.data.avatarUrl);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to upload avatar');
      if (err.response?.data) {
        setResponse(err.response.data);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleExampleClick = (exampleUrl: string) => {
    setImageUrl(exampleUrl);
  };

  const ssrfExamples = [
    {
      name: 'AWS Metadata Service',
      url: 'http://169.254.169.254/latest/meta-data/',
      description: 'Access AWS instance metadata',
      risk: 'Critical'
    },
    {
      name: 'AWS IAM Credentials',
      url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      description: 'Retrieve AWS IAM credentials',
      risk: 'Critical'
    },
    {
      name: 'GCP Metadata',
      url: 'http://metadata.google.internal/computeMetadata/v1/',
      description: 'Access GCP compute metadata',
      risk: 'Critical'
    },
    {
      name: 'Local File - /etc/passwd',
      url: 'file:///etc/passwd',
      description: 'Read system user accounts',
      risk: 'High'
    },
    {
      name: 'Local File - Environment',
      url: 'file:///.env',
      description: 'Read environment variables',
      risk: 'High'
    },
    {
      name: 'Internal Service - Redis',
      url: 'http://localhost:6379/info',
      description: 'Scan internal Redis service',
      risk: 'Medium'
    },
    {
      name: 'Internal Service - MySQL',
      url: 'http://localhost:3306/',
      description: 'Scan internal MySQL service',
      risk: 'Medium'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Upload Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="imageUrl" className="block text-sm font-medium text-gray-700">
            Image URL or File Path
          </label>
          <input
            type="text"
            id="imageUrl"
            value={imageUrl}
            onChange={(e) => setImageUrl(e.target.value)}
            placeholder="https://example.com/image.jpg or file:///path/to/file"
            className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            required
          />
          <p className="mt-1 text-sm text-gray-500">
            Enter any URL or file path. This endpoint is vulnerable to SSRF and LFI attacks.
          </p>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Fetching...' : 'Fetch and Set Avatar'}
        </button>
      </form>

      {/* SSRF Examples */}
      <div>
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center text-sm font-medium text-gray-700 hover:text-gray-900"
        >
          <svg
            className={`mr-2 h-4 w-4 transform transition-transform ${showAdvanced ? 'rotate-90' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          SSRF/LFI Testing Examples
        </button>

        {showAdvanced && (
          <div className="mt-4 space-y-3">
            <div className="bg-gray-50 rounded-md p-4">
              <h4 className="text-sm font-medium text-gray-900 mb-3">Vulnerability Testing Examples</h4>
              <div className="grid grid-cols-1 gap-3">
                {ssrfExamples.map((example, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-white border border-gray-200 rounded-md">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <h5 className="text-sm font-medium text-gray-900">{example.name}</h5>
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                          example.risk === 'Critical' ? 'bg-red-100 text-red-800' :
                          example.risk === 'High' ? 'bg-orange-100 text-orange-800' :
                          'bg-yellow-100 text-yellow-800'
                        }`}>
                          {example.risk}
                        </span>
                      </div>
                      <p className="text-xs text-gray-600 mt-1">{example.description}</p>
                      <code className="text-xs text-gray-500 bg-gray-100 px-1 rounded mt-1 block">
                        {example.url}
                      </code>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleExampleClick(example.url)}
                      className="ml-3 text-xs bg-gray-200 text-gray-700 px-2 py-1 rounded hover:bg-gray-300 transition-colors"
                    >
                      Use
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Upload Failed</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Response Display */}
      {response && (
        <div className="space-y-4">
          {response.success ? (
            <div className="bg-green-50 border border-green-200 rounded-md p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-green-800">Request Successful</h3>
                  <p className="text-sm text-green-700 mt-1">{response.message}</p>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-yellow-800">Request Completed</h3>
                  <p className="text-sm text-yellow-700 mt-1">{response.message}</p>
                </div>
              </div>
            </div>
          )}

          {response.warning && (
            <div className="bg-red-50 border border-red-200 rounded-md p-4">
              <h4 className="text-sm font-medium text-red-800">Security Warning</h4>
              <p className="text-sm text-red-700 mt-1">{response.warning}</p>
            </div>
          )}

          {/* Response Details */}
          <div className="bg-gray-50 rounded-md p-4">
            <h4 className="text-sm font-medium text-gray-900 mb-3">Response Details</h4>
            <div className="space-y-2 text-sm">
              {response.avatarUrl && (
                <div>
                  <span className="font-medium text-gray-700">Avatar URL:</span>
                  <span className="ml-2 text-gray-600">{response.avatarUrl}</span>
                </div>
              )}
              
              {response.filePath && (
                <div>
                  <span className="font-medium text-gray-700">File Path:</span>
                  <span className="ml-2 text-gray-600 font-mono">{response.filePath}</span>
                </div>
              )}

              {response.exploitationInfo && (
                <div>
                  <span className="font-medium text-gray-700">Exploitation Info:</span>
                  <div className="ml-2 mt-1 space-y-1">
                    {response.exploitationInfo.awsCredentials && (
                      <div className="text-red-600">⚠ AWS Credentials Access Detected</div>
                    )}
                    {response.exploitationInfo.instanceMetadata && (
                      <div className="text-red-600">⚠ Instance Metadata Access Detected</div>
                    )}
                    {response.exploitationInfo.gcpMetadata && (
                      <div className="text-red-600">⚠ GCP Metadata Access Detected</div>
                    )}
                  </div>
                </div>
              )}

              {response.networkInfo && (
                <div>
                  <span className="font-medium text-gray-700">Network Info:</span>
                  <div className="ml-2 mt-1 space-y-1 text-xs">
                    {response.networkInfo.targetHost && (
                      <div>Target: {response.networkInfo.targetHost}</div>
                    )}
                    {response.networkInfo.detectedPort && (
                      <div>Port: {response.networkInfo.detectedPort}</div>
                    )}
                    {response.networkInfo.serviceIdentification && (
                      <div>Service: {response.networkInfo.serviceIdentification}</div>
                    )}
                  </div>
                </div>
              )}

              {response.fileInfo && (
                <div>
                  <span className="font-medium text-gray-700">File Info:</span>
                  <div className="ml-2 mt-1 space-y-1 text-xs">
                    {response.fileInfo.fileTypeDetected && (
                      <div>Type: {response.fileInfo.fileTypeDetected}</div>
                    )}
                    {response.fileInfo.contentLength && (
                      <div>Size: {response.fileInfo.contentLength} bytes</div>
                    )}
                    {response.fileInfo.potentiallysensitive && (
                      <div className="text-red-600">⚠ Potentially Sensitive File</div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Raw Content Display */}
            {response.content && (
              <div className="mt-4">
                <h5 className="text-sm font-medium text-gray-900 mb-2">Retrieved Content:</h5>
                <div className="bg-white border border-gray-200 rounded p-3 max-h-64 overflow-y-auto">
                  <pre className="text-xs text-gray-700 whitespace-pre-wrap">{response.content}</pre>
                </div>
              </div>
            )}

            {/* Metadata Display */}
            {response.metadata && (
              <div className="mt-4">
                <h5 className="text-sm font-medium text-gray-900 mb-2">Metadata:</h5>
                <div className="bg-white border border-gray-200 rounded p-3 max-h-64 overflow-y-auto">
                  <pre className="text-xs text-gray-700">{JSON.stringify(response.metadata, null, 2)}</pre>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default AvatarUpload;