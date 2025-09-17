import React, { useState } from 'react';
import { validateAndSanitizeInput } from '../../utils/xssPrevention';

interface SecureCommentFormProps {
  taskId: number;
  onSubmit: (content: string) => Promise<void>;
  allowHtml?: boolean;
  maxLength?: number;
  className?: string;
}

/**
 * Secure Comment Form Component
 * 
 * This component provides secure input handling by:
 * 1. Validating and sanitizing user input
 * 2. Preventing XSS through input validation
 * 3. Providing real-time feedback on input safety
 * 4. Limiting input length and content
 */
const SecureCommentForm: React.FC<SecureCommentFormProps> = ({
  taskId,
  onSubmit,
  allowHtml = false,
  maxLength = 1000,
  className = ''
}) => {
  const [content, setContent] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [sanitizedPreview, setSanitizedPreview] = useState('');

  // Handle input change with real-time validation
  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const inputValue = e.target.value;
    setContent(inputValue);

    // Validate and sanitize input in real-time
    const validation = validateAndSanitizeInput(inputValue, {
      maxLength,
      allowHtml,
      sanitizationLevel: allowHtml ? 'basic' : 'textOnly',
      trimWhitespace: false // Don't trim while typing
    });

    setValidationErrors(validation.errors);
    setSanitizedPreview(validation.sanitizedInput);
  };

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (isSubmitting) return;

    // Final validation
    const validation = validateAndSanitizeInput(content, {
      maxLength,
      allowHtml,
      sanitizationLevel: allowHtml ? 'basic' : 'textOnly',
      trimWhitespace: true
    });

    if (!validation.isValid) {
      setValidationErrors(validation.errors);
      return;
    }

    if (!validation.sanitizedInput.trim()) {
      setValidationErrors(['Comment cannot be empty']);
      return;
    }

    setIsSubmitting(true);
    setValidationErrors([]);

    try {
      // Submit the sanitized content
      await onSubmit(validation.sanitizedInput);
      setContent('');
      setSanitizedPreview('');
    } catch (error) {
      setValidationErrors(['Failed to submit comment. Please try again.']);
    } finally {
      setIsSubmitting(false);
    }
  };

  // Calculate character count and remaining
  const characterCount = content.length;
  const remainingCharacters = maxLength - characterCount;
  const isOverLimit = characterCount > maxLength;

  return (
    <form onSubmit={handleSubmit} className={`secure-comment-form ${className}`}>
      <div className="space-y-4">
        {/* Input field */}
        <div>
          <label htmlFor={`comment-${taskId}`} className="block text-sm font-medium text-gray-700 mb-2">
            Add Comment
            {allowHtml && (
              <span className="ml-2 inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                HTML Allowed (Sanitized)
              </span>
            )}
          </label>
          
          <textarea
            id={`comment-${taskId}`}
            value={content}
            onChange={handleInputChange}
            placeholder={allowHtml ? 
              "Enter your comment (basic HTML allowed)..." : 
              "Enter your comment (text only)..."
            }
            className={`w-full px-3 py-2 border rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 ${
              isOverLimit ? 'border-red-500' : 'border-gray-300'
            }`}
            rows={4}
            disabled={isSubmitting}
          />
          
          {/* Character count */}
          <div className="flex justify-between items-center mt-1">
            <div className="text-xs text-gray-500">
              {allowHtml ? 'Basic HTML tags allowed (b, i, em, strong, u, br, p)' : 'Text only - HTML will be escaped'}
            </div>
            <div className={`text-xs ${isOverLimit ? 'text-red-500' : 'text-gray-500'}`}>
              {characterCount}/{maxLength} characters
              {remainingCharacters < 0 && (
                <span className="ml-1 font-medium">
                  ({Math.abs(remainingCharacters)} over limit)
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Validation errors */}
        {validationErrors.length > 0 && (
          <div className="validation-errors">
            <div className="bg-red-50 border border-red-200 rounded-md p-3">
              <div className="flex">
                <svg className="h-5 w-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">
                    Input Validation Errors
                  </h3>
                  <ul className="mt-2 text-sm text-red-700 list-disc list-inside">
                    {validationErrors.map((error, index) => (
                      <li key={index}>{error}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Preview of sanitized content (in development) */}
        {process.env.NODE_ENV === 'development' && content && sanitizedPreview !== content && (
          <div className="sanitized-preview">
            <details className="bg-blue-50 border border-blue-200 rounded-md p-3">
              <summary className="cursor-pointer text-sm font-medium text-blue-800">
                Preview: Sanitized Content
              </summary>
              <div className="mt-2 p-2 bg-white rounded border text-sm">
                {allowHtml ? (
                  <div dangerouslySetInnerHTML={{ __html: sanitizedPreview }} />
                ) : (
                  <div className="whitespace-pre-wrap">{sanitizedPreview}</div>
                )}
              </div>
            </details>
          </div>
        )}

        {/* Submit button */}
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={isSubmitting || validationErrors.length > 0 || !content.trim() || isOverLimit}
            className={`px-4 py-2 text-sm font-medium rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 ${
              isSubmitting || validationErrors.length > 0 || !content.trim() || isOverLimit
                ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500'
            }`}
          >
            {isSubmitting ? (
              <span className="flex items-center">
                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-gray-500" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Submitting...
              </span>
            ) : (
              'Add Comment'
            )}
          </button>
        </div>

        {/* Security information */}
        <div className="security-info bg-gray-50 rounded-md p-3">
          <div className="flex items-start">
            <svg className="h-5 w-5 text-gray-400 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
            <div className="ml-3">
              <h4 className="text-sm font-medium text-gray-800">Security Features</h4>
              <ul className="mt-1 text-xs text-gray-600 space-y-1">
                <li>• Input is validated and sanitized before submission</li>
                <li>• {allowHtml ? 'HTML content is sanitized to prevent XSS attacks' : 'HTML is escaped to prevent script injection'}</li>
                <li>• Content length is limited to prevent abuse</li>
                <li>• Malicious patterns are automatically detected and blocked</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </form>
  );
};

export default SecureCommentForm;