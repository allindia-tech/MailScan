/**
 * MailTrace Workstation - Interactive SOC Copilot & DFIR Assistant
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Slide-over analyst assistant explaining observed evidence and triage steps.
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  Sparkles,
  Brain,
  X,
  Send,
  HelpCircle,
  ShieldCheck,
  Bot
} from 'lucide-react';
import { EmailAnalysisResult } from '../types/forensics.js';
import { askCopilot } from '../services/api.js';

interface Message {
  role: 'user' | 'model';
  content: string;
}

interface CopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  activeAnalysis?: EmailAnalysisResult;
}

export const CopilotDrawer: React.FC<CopilotDrawerProps> = ({
  isOpen,
  onClose,
  activeAnalysis
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'model',
      content: `Hello Analyst. I am MailTrace Copilot, your technical DFIR assistant.
Grounded in active telemetry for: "${activeAnalysis?.subject || 'Current Selected Email'}" (Threat Score: ${activeAnalysis?.overallRiskScore ?? 90}/100).

How can I assist your investigation? You can query DMARC alignment, inspect originating relay infrastructure, or generate containment playbooks.`
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [deepThinking, setDeepThinking] = useState(false);
  const [modelUsed, setModelUsed] = useState('Gemini Semantic AI');
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSend = async (queryText?: string) => {
    const textToSend = queryText || input;
    if (!textToSend.trim() || loading) return;

    const newMessages: Message[] = [...messages, { role: 'user', content: textToSend }];
    setMessages(newMessages);
    setInput('');
    setLoading(true);

    try {
      const response = await askCopilot(newMessages, activeAnalysis, deepThinking);
      setModelUsed(response.modelUsed || 'Gemini Semantic AI');
      setMessages([...newMessages, { role: 'model', content: response.reply }]);
    } catch {
      setMessages([
        ...newMessages,
        {
          role: 'model',
          content: 'Unable to connect to backend forensic model. Ensure dev server is active.'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handlePreset = (prompt: string) => {
    handleSend(prompt);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[480px] lg:w-[500px] bg-white border-l border-slate-200 shadow-2xl flex flex-col">
      
      {/* Header */}
      <div className="p-3.5 border-b border-slate-200 flex items-center justify-between bg-slate-50">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded bg-indigo-50 border border-indigo-200 text-indigo-600 flex items-center justify-center">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">SOC Copilot</h2>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-indigo-50 text-indigo-700 font-semibold border border-indigo-200 font-mono">
                {deepThinking ? 'Deep Reasoning' : 'Standard'}
              </span>
            </div>
            <p className="text-[10px] text-slate-500 font-mono">{modelUsed}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Deep Thinking Mode Toggle */}
          <button
            onClick={() => setDeepThinking(!deepThinking)}
            className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono transition border ${
              deepThinking
                ? 'bg-indigo-50 text-indigo-700 border-indigo-300 font-semibold'
                : 'bg-white text-slate-600 border-slate-200 hover:text-slate-900 shadow-xs'
            }`}
            title="Toggle high reasoning tier"
          >
            <Brain className="w-3.5 h-3.5 text-indigo-600" />
            <span className="text-[10px]">Reasoning: {deepThinking ? 'ON' : 'OFF'}</span>
          </button>

          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Target Email Subheader */}
      {activeAnalysis && (
        <div className="p-2.5 px-3.5 bg-slate-100/70 border-b border-slate-200 text-[11px] text-slate-600 flex items-center justify-between font-mono">
          <span className="truncate max-w-[340px]">
            Target: <strong className="text-slate-900">{activeAnalysis.subject}</strong>
          </span>
          <span className="px-1.5 py-0.2 rounded bg-rose-50 text-rose-700 border border-rose-200 text-[10px] font-bold">
            {activeAnalysis.overallRiskScore}/100
          </span>
        </div>
      )}

      {/* Messages Container */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3.5 text-xs bg-[#f8f9fc]">
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div className="text-[10px] text-slate-500 mb-1 px-1 uppercase font-bold font-mono">
              {msg.role === 'user' ? 'Analyst' : 'MailTrace Copilot'}
            </div>
            <div
              className={`p-3 rounded-lg max-w-[92%] leading-relaxed shadow-xs ${
                msg.role === 'user'
                  ? 'bg-indigo-600 text-white'
                  : 'bg-white border border-slate-200 text-slate-800 whitespace-pre-wrap font-mono text-[11px]'
              }`}
            >
              {msg.content}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-slate-600 p-2 text-xs font-mono bg-white border border-slate-200 rounded-lg">
            <span className="w-3.5 h-3.5 border-2 border-indigo-600/30 border-t-indigo-600 rounded-full animate-spin" />
            <span>
              {deepThinking ? 'Synthesizing multi-hop forensic reasoning...' : 'Analyzing telemetry...'}
            </span>
          </div>
        )}
        <div ref={chatEndRef} />
      </div>

      {/* Preset Action Chips */}
      <div className="p-2 px-3 bg-slate-50 border-t border-slate-200 flex items-center gap-1.5 overflow-x-auto text-[11px]">
        <button
          onClick={() => handlePreset('Explain the DMARC authentication failure and why the domain is unaligned.')}
          className="px-2.5 py-1 rounded bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 whitespace-nowrap transition shadow-xs"
        >
          Explain DMARC
        </button>
        <button
          onClick={() => handlePreset('Evaluate the earliest reliable sending node IP and explain why it might not be the human attacker.')}
          className="px-2.5 py-1 rounded bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 whitespace-nowrap transition shadow-xs"
        >
          Evaluate Origin IP
        </button>
        <button
          onClick={() => handlePreset('Draft an immediate SOC containment playbook for this threat vector.')}
          className="px-2.5 py-1 rounded bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 whitespace-nowrap transition shadow-xs"
        >
          Containment Playbook
        </button>
      </div>

      {/* Input Form */}
      <div className="p-3 border-t border-slate-200 bg-white">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            placeholder="Ask a question about this email analysis..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            className="flex-1 bg-slate-50 text-slate-900 text-xs rounded px-3 py-2 border border-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-600 focus:bg-white font-mono"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-3 py-2 rounded bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-xs font-semibold transition shadow-xs flex items-center gap-1"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Send</span>
          </button>
        </form>
      </div>

    </div>
  );
};
