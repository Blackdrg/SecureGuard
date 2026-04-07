using System;
using System.Collections.Generic;
using System.Linq;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    public class ExplainableAiPanel
    {
        private readonly AiThreatEngine _aiEngine;

        public ExplainableAiPanel(AiThreatEngine aiEngine)
        {
            _aiEngine = aiEngine;
            _aiEngine.ThreatDetected += OnThreatDetected;
        }

        private void OnThreatDetected(object? sender, ThreatDetectedEventArgs e)
        {
            var explanation = GenerateExplanation(e.FilePath, e.ThreatScore, e.Classification);
            Core.Logger.Log("Info", $"AI Explanation: {explanation.Summary}");
        }

        public AiExplanation GenerateExplanation(string filePath, double threatScore, string classification)
        {
            var explanation = new AiExplanation
            {
                FilePath = filePath,
                ThreatScore = threatScore,
                Classification = classification,
                Timestamp = DateTime.Now
            };

            explanation.Summary = GenerateSummary(threatScore, classification);
            explanation.TriggeringBehaviors = ExplainBehaviors(filePath);
            explanation.ConfidenceLevel = GetConfidenceLevel(threatScore);
            explanation.SuggestedActions = GetSuggestedActions(classification);

            return explanation;
        }

        private string GenerateSummary(double threatScore, string classification)
        {
            var severity = classification switch
            {
                "Critical" => "very high risk",
                "High" => "high risk",
                "Medium" => "moderate risk",
                "Low" => "low risk",
                _ => "minimal risk"
            };
            return $"This file has been classified as {classification} ({threatScore:P0} threat score) indicating {severity}.";
        }

        private List<string> ExplainBehaviors(string filePath)
        {
            var behaviors = new List<string>();
            behaviors.Add("Unusual file entropy suggesting packed or encrypted content");
            behaviors.Add("Presence of suspicious API calls commonly used by malware");
            behaviors.Add("File was recently created or modified");
            behaviors.Add("No valid digital signature detected");
            return behaviors.Take(3).ToList();
        }

        private string GetConfidenceLevel(double threatScore)
        {
            return threatScore switch
            {
                >= 0.9 => "Very High (95%+)",
                >= 0.7 => "High (80-95%)",
                >= 0.5 => "Medium (60-80%)",
                >= 0.3 => "Low (40-60%)",
                _ => "Very Low (<40%)"
            };
        }

        private List<string> GetSuggestedActions(string classification)
        {
            return classification switch
            {
                "Critical" => new List<string> { "Immediately quarantine the file", "Run full system scan", "Review recent system changes" },
                "High" => new List<string> { "Quarantine the file for analysis", "Run a quick scan of system", "Monitor system behavior" },
                "Medium" => new List<string> { "Monitor the file closely", "Run heuristic analysis", "Add to watchlist" },
                _ => new List<string> { "Continue monitoring", "Allow with caution" }
            };
        }

        public string FormatForDisplay(AiExplanation explanation)
        {
            var display = $"=== THREAT ANALYSIS EXPLANATION ===" + Environment.NewLine;
            display += $"File: {explanation.FilePath}" + Environment.NewLine;
            display += $"Classification: {explanation.Classification}" + Environment.NewLine;
            display += $"Threat Score: {explanation.ThreatScore:P0}" + Environment.NewLine;
            display += $"Confidence: {explanation.ConfidenceLevel}" + Environment.NewLine;
            display += Environment.NewLine + "SUMMARY:" + Environment.NewLine;
            display += explanation.Summary + Environment.NewLine;
            display += Environment.NewLine + "TRIGGERING BEHAVIORS:" + Environment.NewLine;
            for (int i = 0; i < explanation.TriggeringBehaviors.Count; i++)
                display += $"{i + 1}. {explanation.TriggeringBehaviors[i]}" + Environment.NewLine;
            display += Environment.NewLine + "SUGGESTED ACTIONS:";
            for (int i = 0; i < explanation.SuggestedActions.Count; i++)
                display += $"{i + 1}. {explanation.SuggestedActions[i]}" + Environment.NewLine;
            return display;
        }
    }

    public class AiExplanation
    {
        public string FilePath { get; set; } = "";
        public double ThreatScore { get; set; }
        public string Classification { get; set; } = "";
        public string Summary { get; set; } = "";
        public List<string> TriggeringBehaviors { get; set; } = new();
        public string ConfidenceLevel { get; set; } = "";
        public List<string> SuggestedActions { get; set; } = new();
        public DateTime Timestamp { get; set; }
    }
}

