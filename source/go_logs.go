package main

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	DEFAULT_SYSLOG_PATHS = []string{
		"/var/log/messages",
		"/var/log/syslog",
		"/var/log/system.log",
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/kern.log",
		"/var/log/dmesg",
		"/var/log/debug",
	}

	MONTHS = map[string]time.Month{
		"Jan": time.January, "Feb": time.February, "Mar": time.March,
		"Apr": time.April,   "May": time.May,      "Jun": time.June,
		"Jul": time.July,    "Aug": time.August,   "Sep": time.September,
		"Oct": time.October, "Nov": time.November, "Dec": time.December,
	}
)

type SecurityError struct {
	Message string
}

func (e SecurityError) Error() string {
	return e.Message
}

type RSyslogInfo struct {
	Version          string
	Features         map[string]bool
	ConfigFile       string
	PidFile          string
	Platform         string
	RainerscriptBits int
}

func (r *RSyslogInfo) DetectRSyslogInfo() bool {
	cmd := exec.Command("rsyslogd", "-v")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return r.parseVersionOutput(string(output))
	}
	return r.detectFromSystem()
}

func (r *RSyslogInfo) parseVersionOutput(output string) bool {
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return false
	}

	versionMatch := regexp.MustCompile(`rsyslogd\s+([\d.]+)`).FindStringSubmatch(lines[0])
	if len(versionMatch) > 1 {
		r.Version = versionMatch[1]
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Config file:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				r.ConfigFile = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "PID file:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				r.PidFile = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Number of Bits in RainerScript integers:") {
			bitsMatch := regexp.MustCompile(`(\d+)`).FindStringSubmatch(line)
			if len(bitsMatch) > 1 {
				r.RainerscriptBits, _ = strconv.Atoi(bitsMatch[1])
			}
		} else if strings.Contains(line, ":") && (strings.Contains(line, "Yes") || strings.Contains(line, "No")) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				feature := strings.TrimSpace(parts[0])
				value := strings.Contains(parts[1], "Yes")
				if r.Features == nil {
					r.Features = make(map[string]bool)
				}
				r.Features[feature] = value
			}
		}
	}

	return true
}

func (r *RSyslogInfo) detectFromSystem() bool {
	cmd := exec.Command("pgrep", "rsyslog")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		r.Version = "unknown (running)"

		possibleConfigs := []string{
			"/etc/rsyslog.conf",
			"/etc/rsyslog.d/",
			"/usr/local/etc/rsyslog.conf",
		}
		for _, config := range possibleConfigs {
			if _, err := os.Stat(config); err == nil {
				r.ConfigFile = config
				break
			}
		}
		return true
	}
	return false
}

type PatternInfo struct {
	Pattern     *regexp.Regexp
	Type        string
	Description string
}

func (r *RSyslogInfo) GetRecommendedPatterns() []PatternInfo {
	patterns := []PatternInfo{}

	patterns = append(patterns, PatternInfo{
		Pattern: regexp.MustCompile(
			`^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+` +
				`(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+` +
				`(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)` +
				`(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$`),
		Type:        "traditional",
		Description: "Basic syslog format",
	})

	patterns = append(patterns, PatternInfo{
		Pattern: regexp.MustCompile(
			`^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+` +
				`(?P<time>\d{2}:\d{2}:\d{2})\s+` +
				`(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s*` +
				`(?P<message>.+)$`),
		Type:        "traditional_simple",
		Description: "Simple syslog format",
	})

	if r.Version != "" && r.versionCompare(r.Version, "8.0") >= 0 {
		patterns = append(patterns, PatternInfo{
			Pattern: regexp.MustCompile(
				`^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?(?:\s+[+-]\d{4})?)\s+` +
					`(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)(?:\[(?P<pid>\d+)\])?:\s*` +
					`(?P<message>.+)$`),
			Type:        "iso8601",
			Description: "ISO 8601 timestamp format",
		})

		patterns = append(patterns, PatternInfo{
			Pattern: regexp.MustCompile(
				`^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4})\s+` +
					`(?P<host>[\w\-.]+)\s+(?P<service>\w+)\[(?P<pid>\d+)\]:\s*` +
					`(?P<message>.+)$`),
			Type:        "journald",
			Description: "Journald-style format",
		})
	}

	if r.Features["FEATURE_REGEXP"] {
		patterns = append(patterns, PatternInfo{
			Pattern: regexp.MustCompile(
				`^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\d+-:]+)\s+` +
					`(?P<host>\S+)\s+` +
					`(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:?\s+` +
					`(?:\[(?P<level>\w+)\]\s+)?` +
					`(?P<message>.+)$`),
			Type:        "rainerscript_enhanced",
			Description: "RainerScript enhanced format",
		})
	}

	return patterns
}

func (r *RSyslogInfo) versionCompare(v1, v2 string) int {
	normalize := func(v string) []int {
		clean := regexp.MustCompile(`[^0-9.]`).ReplaceAllString(v, "")
		parts := strings.Split(clean, ".")
		result := make([]int, len(parts))
		for i, part := range parts {
			result[i], _ = strconv.Atoi(part)
		}
		return result
	}

	v1Norm := normalize(v1)
	v2Norm := normalize(v2)

	maxLen := len(v1Norm)
	if len(v2Norm) > maxLen {
		maxLen = len(v2Norm)
	}

	for i := 0; i < maxLen; i++ {
		v1Part := 0
		if i < len(v1Norm) {
			v1Part = v1Norm[i]
		}
		v2Part := 0
		if i < len(v2Norm) {
			v2Part = v2Norm[i]
		}
		if v1Part != v2Part {
			return v1Part - v2Part
		}
	}
	return 0
}

func (r *RSyslogInfo) GetConfigRecommendations() map[string]string {
	recommendations := make(map[string]string)

	if r.Version != "" && r.versionCompare(r.Version, "8.0") < 0 {
		recommendations["version"] = "Consider upgrading to rsyslog 8.x+ for better features"
	}

	if !r.Features["FEATURE_REGEXP"] {
		recommendations["regexp"] = "Rebuild rsyslog with regexp support for better parsing"
	}

	if r.ConfigFile != "" {
		content, err := os.ReadFile(r.ConfigFile)
		if err == nil {
			configContent := string(content)
			if !strings.Contains(configContent, "imfile") {
				recommendations["imfile"] = "Consider enabling imfile module for file monitoring"
			}
			if strings.Contains(configContent, "omelasticsearch") {
				recommendations["elastic"] = "Elasticsearch output detected - consider using elastic tools"
			}
		}
	}

	return recommendations
}

type AnalyzerConfig struct {
	MaxDays             int
	TruncateLength      int
	ShowFullLines       bool
	WrapLines           bool
	MaxLinesPerService  int
	ColorOutput         bool
	Verbose             bool
	EnableAnalysis      bool
	MaxFileSizeMB       int
	UseRSyslogDetection bool
	MaxMemoryEntries    int
}

func NewDefaultConfig() *AnalyzerConfig {
	return &AnalyzerConfig{
		MaxDays:             30,
		TruncateLength:      80,
		ShowFullLines:       false,
		WrapLines:           false,
		MaxLinesPerService:  5,
		ColorOutput:         true,
		Verbose:             false,
		EnableAnalysis:      false,
		MaxFileSizeMB:       100,
		UseRSyslogDetection: true,
		MaxMemoryEntries:    100000,
	}
}

func (c *AnalyzerConfig) FromFile(configPath string) error {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(content, c)
}

type LogEntry struct {
	Timestamp time.Time
	Service   string
	Message   string
	Level     string
	Host      string
	PID       string
	RawLine   string
}

func (l *LogEntry) IsError() bool {
	if l.Level != "" {
		upperLevel := strings.ToUpper(l.Level)
		return upperLevel == "ERROR" || upperLevel == "CRITICAL" || upperLevel == "FATAL"
	}
	errorIndicators := []string{"error", "failed", "failure", "exception", "critical", "panic"}
	lowerMessage := strings.ToLower(l.Message)
	for _, indicator := range errorIndicators {
		if strings.Contains(lowerMessage, indicator) {
			return true
		}
	}
	return false
}

type AnalysisResults struct {
	TotalEntries       int
	UniqueServices     map[string]bool
	DateRange          [2]string
	ServiceCounts      map[string]int
	ErrorCount         int
	LevelDistribution  map[string]int
	HourlyDistribution map[string]int
	mu                 sync.RWMutex
}

func NewAnalysisResults() *AnalysisResults {
	return &AnalysisResults{
		UniqueServices:     make(map[string]bool),
		ServiceCounts:      make(map[string]int),
		LevelDistribution:  make(map[string]int),
		HourlyDistribution: make(map[string]int),
	}
}

func (a *AnalysisResults) Update(entry *LogEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.TotalEntries++
	a.UniqueServices[entry.Service] = true
	a.ServiceCounts[entry.Service]++

	if entry.Level != "" {
		upperLevel := strings.ToUpper(entry.Level)
		a.LevelDistribution[upperLevel]++
	}

	if entry.IsError() {
		a.ErrorCount++
	}

	hourKey := entry.Timestamp.Format("15:00")
	a.HourlyDistribution[hourKey]++
}

type AnalysisPlugin interface {
	ProcessEntry(entry *LogEntry)
	GetResults() map[string]interface{}
}

type ErrorClusterPlugin struct {
	ErrorPatterns map[string]int
	ServiceErrors map[string]map[string]int
	mu            sync.RWMutex
}

func NewErrorClusterPlugin() *ErrorClusterPlugin {
	return &ErrorClusterPlugin{
		ErrorPatterns: make(map[string]int),
		ServiceErrors: make(map[string]map[string]int),
	}
}

func (e *ErrorClusterPlugin) ProcessEntry(entry *LogEntry) {
	if !entry.IsError() {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	pattern := e.extractErrorPattern(entry.Message)
	e.ErrorPatterns[pattern]++

	if e.ServiceErrors[entry.Service] == nil {
		e.ServiceErrors[entry.Service] = make(map[string]int)
	}
	e.ServiceErrors[entry.Service][pattern]++
}

func (e *ErrorClusterPlugin) extractErrorPattern(message string) string {
	words := strings.Fields(message)
	if len(words) > 3 {
		return strings.Join(words[:3], " ") + "..."
	}
	return message
}

func (e *ErrorClusterPlugin) GetResults() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	topPatterns := make(map[string]int)
	patterns := make([]string, 0, len(e.ErrorPatterns))
	for pattern := range e.ErrorPatterns {
		patterns = append(patterns, pattern)
	}
	sort.Slice(patterns, func(i, j int) bool {
		return e.ErrorPatterns[patterns[i]] > e.ErrorPatterns[patterns[j]]
	})
	for i, pattern := range patterns {
		if i >= 10 {
			break
		}
		topPatterns[pattern] = e.ErrorPatterns[pattern]
	}

	serviceErrors := make(map[string]map[string]int)
	for service, patterns := range e.ServiceErrors {
		serviceErrors[service] = make(map[string]int)
		for pattern, count := range patterns {
			serviceErrors[service][pattern] = count
		}
	}

	return map[string]interface{}{
		"top_error_patterns": topPatterns,
		"service_errors":     serviceErrors,
	}
}

type LogParser struct {
	CurrentYear        int
	Verbose            bool
	UseRSyslogDetection bool
	RSyslogInfo        *RSyslogInfo
	CompiledPatterns   []PatternInfo
}

func NewLogParser(currentYear int, verbose, useRSyslogDetection bool) *LogParser {
	parser := &LogParser{
		CurrentYear:        currentYear,
		Verbose:            verbose,
		UseRSyslogDetection: useRSyslogDetection,
	}

	if useRSyslogDetection {
		parser.RSyslogInfo = &RSyslogInfo{}
		if parser.RSyslogInfo.DetectRSyslogInfo() && verbose {
			log.Printf("Detected rsyslogd version: %s", parser.RSyslogInfo.Version)
		}
	}

	parser.CompiledPatterns = parser.compilePatterns()
	return parser
}

func (l *LogParser) compilePatterns() []PatternInfo {
	if l.RSyslogInfo != nil {
		return l.RSyslogInfo.GetRecommendedPatterns()
	}

	return []PatternInfo{
		{
			Pattern: regexp.MustCompile(
				`^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+` +
					`(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+` +
					`(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)` +
					`(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$`),
			Type:        "traditional",
			Description: "Basic syslog format",
		},
		{
			Pattern: regexp.MustCompile(
				`^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+` +
					`(?P<time>\d{2}:\d{2}:\d{2})\s+` +
					`(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s*` +
					`(?P<message>.+)$`),
			Type:        "traditional_simple",
			Description: "Simple syslog format",
		},
		{
			Pattern: regexp.MustCompile(
				`^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?(?:\s+[+-]\d{4})?)\s+` +
					`(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)(?:\[(?P<pid>\d+)\])?:\s*` +
					`(?P<message>.+)$`),
			Type:        "iso8601",
			Description: "ISO 8601 timestamp format",
		},
	}
}

func (l *LogParser) parseIsoTimestamp(tsStr string) *time.Time {
	tsStr = strings.Replace(tsStr, " ", "T", 1)

	formats := []string{
		"2006-01-02T15:04:05.999999Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05.999999-0700",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, tsStr); err == nil {
			return &t
		}
	}
	return nil
}

func (l *LogParser) ParseLine(line string, now, cutoffDate time.Time) *LogEntry {
	if !l.isLikelyLogLine(line) {
		return nil
	}

	for _, patternInfo := range l.CompiledPatterns {
		match := patternInfo.Pattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		groupDict := make(map[string]string)
		for i, name := range patternInfo.Pattern.SubexpNames() {
			if i > 0 && i <= len(match) && name != "" {
				groupDict[name] = match[i]
			}
		}

		timestamp := l.extractTimestamp(groupDict, patternInfo.Type, now)
		if timestamp == nil || timestamp.Before(cutoffDate) || timestamp.After(now.Add(24*time.Hour)) {
			return nil
		}

		return &LogEntry{
			Timestamp: *timestamp,
			Service:   strings.TrimSpace(groupDict["service"]),
			Message:   strings.TrimSpace(groupDict["message"]),
			Level:     groupDict["level"],
			Host:      groupDict["host"],
			PID:       groupDict["pid"],
			RawLine:   line,
		}
	}

	return nil
}

func (l *LogParser) isLikelyLogLine(line string) bool {
	if line == "" || len(line) < 15 {
		return false
	}

	if len(line) >= 3 {
		firstThree := line[:3]
		if _, exists := MONTHS[firstThree]; exists {
			return true
		}
	}

	return regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`).MatchString(line)
}

func (l *LogParser) extractTimestamp(groupDict map[string]string, patternType string, now time.Time) *time.Time {
	if patternType == "iso8601" || patternType == "journald" || patternType == "rainerscript_enhanced" {
		return l.parseIsoTimestamp(groupDict["timestamp"])
	}

	month := groupDict["month"]
	day := groupDict["day"]
	timeStr := groupDict["time"]

	year := now.Year()
	if monthNum, exists := map[string]int{
		"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
		"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
	}[month]; exists {
		if monthNum > int(now.Month()) {
			year--
		}
	}

	var baseTime string
	var microseconds int
	if strings.Contains(timeStr, ".") {
		timeParts := strings.Split(timeStr, ".")
		baseTime = timeParts[0]
		microStr := timeParts[1]
		if len(microStr) > 6 {
			microStr = microStr[:6]
		}
		microStr = microStr + strings.Repeat("0", 6-len(microStr))
		microseconds, _ = strconv.Atoi(microStr)
	} else {
		baseTime = timeStr
		microseconds = 0
	}

	tsStr := fmt.Sprintf("%d %s %s %s", year, month, day, baseTime)
	t, err := time.Parse("2006 Jan 2 15:04:05", tsStr)
	if err != nil {
		return nil
	}
	result := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), microseconds*1000, t.Location())
	return &result
}

func (l *LogParser) GetParserInfo() map[string]interface{} {
	patternTypes := make([]string, len(l.CompiledPatterns))
	patternDescriptions := make([]string, len(l.CompiledPatterns))

	for i, pattern := range l.CompiledPatterns {
		patternTypes[i] = pattern.Type
		patternDescriptions[i] = pattern.Description
	}

	info := map[string]interface{}{
		"patterns_loaded":      len(l.CompiledPatterns),
		"pattern_types":        patternTypes,
		"pattern_descriptions": patternDescriptions,
	}

	if l.RSyslogInfo != nil {
		info["rsyslog_detected"] = true
		info["rsyslog_version"] = l.RSyslogInfo.Version
		info["rsyslog_features"] = l.RSyslogInfo.Features
		info["recommendations"] = l.RSyslogInfo.GetConfigRecommendations()
	} else {
		info["rsyslog_detected"] = false
	}

	return info
}

type RSyslogAnalyzer struct {
	Tree            map[string]map[string][]*LogEntry
	Config          *AnalyzerConfig
	LogFile         string
	CurrentYear     int
	Parser          *LogParser
	AnalysisResults *AnalysisResults
	Plugins         []AnalysisPlugin
	ProcessedLines  int
	ParsedEntries   int
	MemoryWarning   bool
	mu              sync.RWMutex
}

func NewRSyslogAnalyzer(logFile string, config *AnalyzerConfig) *RSyslogAnalyzer {
	if config == nil {
		config = NewDefaultConfig()
	}

	currentYear := time.Now().Year()
	analyzer := &RSyslogAnalyzer{
		Tree:            make(map[string]map[string][]*LogEntry),
		Config:          config,
		LogFile:         logFile,
		CurrentYear:     currentYear,
		Parser:          NewLogParser(currentYear, config.Verbose, config.UseRSyslogDetection),
		AnalysisResults: NewAnalysisResults(),
		Plugins:         []AnalysisPlugin{NewErrorClusterPlugin()},
	}

	if analyzer.LogFile == "" {
		analyzer.LogFile = analyzer.findLogFile()
	}

	return analyzer
}

func (r *RSyslogAnalyzer) isReadableLog(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func (r *RSyslogAnalyzer) getRecentDates() []string {
	dates := make([]string, 7)
	for i := 0; i < 7; i++ {
		date := time.Now().AddDate(0, 0, -i).Format("20060102")
		dates[i] = date
	}
	return dates
}

func (r *RSyslogAnalyzer) findLogFile() string {
	candidates := make([]struct {
		Path  string
		Mtime time.Time
	}, 0)

	for _, path := range DEFAULT_SYSLOG_PATHS {
		if r.isReadableLog(path) {
			if info, err := os.Stat(path); err == nil {
				candidates = append(candidates, struct {
					Path  string
					Mtime time.Time
				}{Path: path, Mtime: info.ModTime()})
			}
		}

		patterns := make([]string, 0)
		for _, ext := range []string{"1", "2", "3", "0"} {
			patterns = append(patterns, path+"."+ext)
		}
		for _, date := range r.getRecentDates() {
			patterns = append(patterns, path+"-"+date)
		}

		for _, pattern := range patterns {
			if r.isReadableLog(pattern) {
				if info, err := os.Stat(pattern); err == nil {
					candidates = append(candidates, struct {
						Path  string
						Mtime time.Time
					}{Path: pattern, Mtime: info.ModTime()})
				}
			}
		}
	}

	for _, candidate := range candidates {
		for _, ext := range []string{".gz", ".bz2", ".xz"} {
			compressedPath := candidate.Path + ext
			if r.isReadableLog(compressedPath) {
				if info, err := os.Stat(compressedPath); err == nil {
					candidates = append(candidates, struct {
						Path  string
						Mtime time.Time
					}{Path: compressedPath, Mtime: info.ModTime()})
				}
			}
		}
	}

	if len(candidates) == 0 {
		log.Printf("No standard syslog file found or insufficient permissions.")
		return ""
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Mtime.After(candidates[j].Mtime)
	})

	selected := candidates[0].Path
	log.Printf("Using log file: %s", selected)
	return selected
}

func (r *RSyslogAnalyzer) isSafePath(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	allowedDirs := []string{"/var/log", "/tmp/logs", "/opt/logs"}
	for _, allowed := range allowedDirs {
		if strings.HasPrefix(resolved, allowed) {
			return true
		}
	}
	return false
}

func (r *RSyslogAnalyzer) openLogFile(filePath string) (io.ReadCloser, error) {
	resolvedPath, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		return nil, err
	}

	if !r.isSafePath(resolvedPath) {
		return nil, SecurityError{Message: fmt.Sprintf("Access to %s not allowed", filePath)}
	}

	info, err := os.Stat(resolvedPath)
	if err != nil {
		return nil, err
	}

	fileSizeMB := info.Size() / (1024 * 1024)
	if fileSizeMB > int64(r.Config.MaxFileSizeMB) {
		return nil, SecurityError{Message: fmt.Sprintf("File too large: %dMB > %dMB limit", fileSizeMB, r.Config.MaxFileSizeMB)}
	}

	file, err := os.Open(resolvedPath)
	if err != nil {
		return nil, err
	}

	if strings.HasSuffix(filePath, ".gz") {
		return gzip.NewReader(file)
	} else if strings.HasSuffix(filePath, ".bz2") {
		return struct {
			io.Reader
			io.Closer
		}{
			Reader: bzip2.NewReader(file),
			Closer: file,
		}, nil
	} else if strings.HasSuffix(filePath, ".xz") {
		return file, errors.New("xz compression not supported in standard library")
	}

	return file, nil
}

func (r *RSyslogAnalyzer) LoadLogs() error {
	if r.LogFile == "" {
		return fmt.Errorf("no log file specified or found")
	}

	if _, err := os.Stat(r.LogFile); err != nil {
		return fmt.Errorf("log file does not exist: %s", r.LogFile)
	}

	info, err := os.Stat(r.LogFile)
	if err != nil {
		return fmt.Errorf("cannot access log file: %v", err)
	}

	if info.Size() > 1024*1024 {
		fmt.Print("Parsing logs...")
		defer fmt.Println(" done")
	}

	reader, err := r.openLogFile(r.LogFile)
	if err != nil {
		return fmt.Errorf("cannot read log file: %v", err)
	}
	defer reader.Close()

	now := time.Now()
	cutoffDate := now.AddDate(0, 0, -r.Config.MaxDays)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		r.ProcessedLines++
		line := scanner.Text()
		entry := r.Parser.ParseLine(strings.TrimSpace(line), now, cutoffDate)
		if entry != nil {
			r.processEntry(entry)
		}
	}

	if err := scanner.Err(); err != nil && r.Config.Verbose {
		log.Printf("Scanner error: %v", err)
	}

	if r.Config.Verbose {
		successRate := 0.0
		if r.ProcessedLines > 0 {
			successRate = float64(r.ParsedEntries) / float64(r.ProcessedLines) * 100
		}
		log.Printf("Processed %d lines, parsed %d entries (%.1f%% success rate)", r.ProcessedLines, r.ParsedEntries, successRate)
	}

	return nil
}

func (r *RSyslogAnalyzer) processEntry(entry *LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ParsedEntries >= r.Config.MaxMemoryEntries {
		if !r.MemoryWarning {
			log.Printf("Memory limit reached (%d entries). Stopping processing.", r.Config.MaxMemoryEntries)
			r.MemoryWarning = true
		}
		return
	}

	r.ParsedEntries++
	dateKey := entry.Timestamp.Format("2006-01-02")
	if r.Tree[dateKey] == nil {
		r.Tree[dateKey] = make(map[string][]*LogEntry)
	}
	r.Tree[dateKey][entry.Service] = append(r.Tree[dateKey][entry.Service], entry)

	if r.Config.EnableAnalysis {
		r.AnalysisResults.Update(entry)
	}

	for _, plugin := range r.Plugins {
		plugin.ProcessEntry(entry)
	}
}

func (r *RSyslogAnalyzer) BuildTree() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, services := range r.Tree {
		for _, logs := range services {
			sort.Slice(logs, func(i, j int) bool {
				return logs[i].Timestamp.Before(logs[j].Timestamp)
			})
		}
	}

	if len(r.Tree) > 0 && r.Config.EnableAnalysis {
		dates := make([]string, 0, len(r.Tree))
		for date := range r.Tree {
			dates = append(dates, date)
		}
		sort.Strings(dates)
		r.AnalysisResults.DateRange = [2]string{dates[0], dates[len(dates)-1]}
	}
}

func (r *RSyslogAnalyzer) DisplaySystemInfo() {
	parserInfo := r.Parser.GetParserInfo()

	if r.Config.ColorOutput {
		r.displayColorSystemInfo(parserInfo)
	} else {
		r.displayTextSystemInfo(parserInfo)
	}
}

func (r *RSyslogAnalyzer) displayColorSystemInfo(parserInfo map[string]interface{}) {
	fmt.Println("\n=== System Information ===")
	fmt.Printf("Patterns loaded: %v\n", parserInfo["patterns_loaded"])
	fmt.Printf("Pattern types: %v\n", strings.Join(parserInfo["pattern_types"].([]string), ", "))
	fmt.Printf("RSyslog detected: %v\n", parserInfo["rsyslog_detected"])

	if parserInfo["rsyslog_detected"].(bool) {
		fmt.Printf("RSyslog version: %v\n", parserInfo["rsyslog_version"])
		fmt.Printf("RainerScript bits: %v\n", r.Parser.RSyslogInfo.RainerscriptBits)
	}

	fmt.Println("\nPattern Descriptions:")
	for i, desc := range parserInfo["pattern_descriptions"].([]string) {
		fmt.Printf("  %d. %s\n", i+1, desc)
	}

	if recommendations, ok := parserInfo["recommendations"].(map[string]string); ok {
		fmt.Println("\nRecommendations:")
		for _, recommendation := range recommendations {
			fmt.Printf("  • %s\n", recommendation)
		}
	}
}

func (r *RSyslogAnalyzer) displayTextSystemInfo(parserInfo map[string]interface{}) {
	fmt.Println("\nSystem Information:")
	fmt.Printf("  Patterns loaded: %v\n", parserInfo["patterns_loaded"])
	fmt.Printf("  Pattern types: %v\n", strings.Join(parserInfo["pattern_types"].([]string), ", "))
	fmt.Printf("  RSyslog detected: %v\n", parserInfo["rsyslog_detected"])

	if parserInfo["rsyslog_detected"].(bool) {
		fmt.Printf("  RSyslog version: %v\n", parserInfo["rsyslog_version"])
		fmt.Printf("  RainerScript bits: %v\n", r.Parser.RSyslogInfo.RainerscriptBits)
	}

	fmt.Println("\nPattern Descriptions:")
	for i, desc := range parserInfo["pattern_descriptions"].([]string) {
		fmt.Printf("  %d. %s\n", i+1, desc)
	}

	if recommendations, ok := parserInfo["recommendations"].(map[string]string); ok {
		fmt.Println("\nRecommendations:")
		for _, recommendation := range recommendations {
			fmt.Printf("  • %s\n", recommendation)
		}
	}
}

func (r *RSyslogAnalyzer) DisplayTree() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.Tree) == 0 {
		fmt.Println("No logs to display.")
		return
	}

	if r.Config.ColorOutput {
		fmt.Println("\n=== Syslog Analysis Tree ===")
	} else {
		fmt.Println("Syslog Analysis Tree")
		fmt.Println(strings.Repeat("=", 50))
	}

	dates := make([]string, 0, len(r.Tree))
	for date := range r.Tree {
		dates = append(dates, date)
	}
	sort.Strings(dates)

	for _, date := range dates {
		fmt.Printf("\n%s\n", date)
		services := r.Tree[date]

		serviceNames := make([]string, 0, len(services))
		for service := range services {
			serviceNames = append(serviceNames, service)
		}
		sort.Strings(serviceNames)

		for i, service := range serviceNames {
			logs := services[service]
			errorCount := 0
			for _, log := range logs {
				if log.IsError() {
					errorCount++
				}
			}

			serviceDisplay := service
			if errorCount > 0 {
				serviceDisplay += fmt.Sprintf(" [errors: %d]", errorCount)
			}

			connector := "├── "
			if i == len(serviceNames)-1 {
				connector = "└── "
			}
			fmt.Printf("%s%s\n", connector, serviceDisplay)
			r.displayServiceLogs(logs, i == len(serviceNames)-1)
		}
	}
	fmt.Println()
}

func (r *RSyslogAnalyzer) displayServiceLogs(logs []*LogEntry, isLastService bool) {
	displayedCount := len(logs)
	if displayedCount > r.Config.MaxLinesPerService {
		displayedCount = r.Config.MaxLinesPerService
	}

	for i, log := range logs[:displayedCount] {
		isLastLog := i == displayedCount-1
		prefix := "│   "
		if isLastService {
			prefix = "    "
		}
		if isLastLog {
			prefix += "└── "
		} else {
			prefix += "├── "
		}

		r.displayLogEntry(log, prefix, isLastLog)
	}

	if len(logs) > r.Config.MaxLinesPerService {
		overflowCount := len(logs) - r.Config.MaxLinesPerService
		errorCount := 0
		for _, log := range logs[r.Config.MaxLinesPerService:] {
			if log.IsError() {
				errorCount++
			}
		}

		overflowMsg := fmt.Sprintf("... (%d more logs", overflowCount)
		if errorCount > 0 {
			overflowMsg += fmt.Sprintf(", %d errors", errorCount)
		}
		overflowMsg += ")"

		prefix := "│   "
		if isLastService {
			prefix = "    "
		}
		fmt.Printf("%s└── %s\n", prefix, overflowMsg)
	}
}

func wrapText(text string, width int) []string {
	if len(text) <= width {
		return []string{text}
	}

	lines := []string{}
	currentLine := ""
	words := strings.Fields(text)

	for _, word := range words {
		if len(currentLine)+len(word)+1 <= width {
			if currentLine != "" {
				currentLine += " " + word
			} else {
				currentLine = word
			}
		} else {
			if currentLine != "" {
				lines = append(lines, currentLine)
			}
			currentLine = word
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}

func (r *RSyslogAnalyzer) displayLogEntry(log *LogEntry, prefix string, isLast bool) {
	timestamp := log.Timestamp.Format("15:04:05")
	levelIndicator := ""
	if log.Level != "" {
		levelIndicator = "[" + log.Level + "] "
	}

	var messageLines []string
	var truncation string
	if r.Config.ShowFullLines {
		messageLines = []string{log.Message}
		truncation = ""
	} else if r.Config.WrapLines {
		wrapWidth := 40
		if r.Config.TruncateLength-len(prefix)-len(timestamp)-len(levelIndicator)-3 > wrapWidth {
			wrapWidth = r.Config.TruncateLength - len(prefix) - len(timestamp) - len(levelIndicator) - 3
		}
		messageLines = wrapText(log.Message, wrapWidth)
		truncation = ""
	} else {
		if len(log.Message) > r.Config.TruncateLength {
			messageLines = []string{log.Message[:r.Config.TruncateLength]}
			truncation = "..."
		} else {
			messageLines = []string{log.Message}
			truncation = ""
		}
	}

	firstLine := fmt.Sprintf("%s[%s] %s%s%s", prefix, timestamp, levelIndicator, messageLines[0], truncation)
	r.printLine(firstLine, r.getStyleForLog(log))

	if r.Config.WrapLines && len(messageLines) > 1 {
		connector := "       "
		if !isLast {
			connector = "│      "
		}
		for _, line := range messageLines[1:] {
			fmt.Printf("│   %s%s\n", connector, line)
		}
	}
}

func (r *RSyslogAnalyzer) getStyleForLog(log *LogEntry) string {
	if log.Level != "" {
		levelStyles := map[string]string{
			"ERROR":    "\033[31m",
			"ERR":      "\033[31m",
			"FATAL":    "\033[1;31m",
			"WARN":     "\033[33m",
			"WARNING":  "\033[33m",
			"INFO":     "\033[32m",
			"DEBUG":    "\033[34m",
			"CRIT":     "\033[1;31m",
			"CRITICAL": "\033[1;31m",
		}
		if style, ok := levelStyles[strings.ToUpper(log.Level)]; ok {
			return style
		}
	}

	errorIndicators := []string{"error", "failed", "failure", "exception", "critical"}
	lowerMessage := strings.ToLower(log.Message)
	for _, indicator := range errorIndicators {
		if strings.Contains(lowerMessage, indicator) {
			return "\033[31m"
		}
	}

	return "\033[0m"
}

func (r *RSyslogAnalyzer) printLine(text, style string) {
	if r.Config.ColorOutput && style != "" {
		fmt.Printf("%s%s\033[0m\n", style, text)
	} else {
		fmt.Println(text)
	}
}

func (r *RSyslogAnalyzer) DisplaySummary() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.Tree) == 0 {
		fmt.Println("No logs found.")
		return
	}

	if r.Config.ColorOutput {
		r.displayColorSummary()
	} else {
		r.displayTextSummary()
	}
}

func (r *RSyslogAnalyzer) displayColorSummary() {
	fmt.Println("\n=== Log Analysis Summary ===")
	fmt.Printf("Total entries: %d\n", r.AnalysisResults.TotalEntries)
	fmt.Printf("Unique services: %d\n", len(r.AnalysisResults.UniqueServices))
	fmt.Printf("Date range: %s to %s\n", r.AnalysisResults.DateRange[0], r.AnalysisResults.DateRange[1])
	fmt.Printf("Days with logs: %d\n", len(r.Tree))
	fmt.Printf("Error count: %d\n", r.AnalysisResults.ErrorCount)

	topServices := make([]struct {
		Service string
		Count   int
	}, 0, len(r.AnalysisResults.ServiceCounts))
	for service, count := range r.AnalysisResults.ServiceCounts {
		topServices = append(topServices, struct {
			Service string
			Count   int
		}{Service: service, Count: count})
	}
	sort.Slice(topServices, func(i, j int) bool {
		return topServices[i].Count > topServices[j].Count
	})
	if len(topServices) > 5 {
		topServices = topServices[:5]
	}
	servicesStr := ""
	for i, s := range topServices {
		if i > 0 {
			servicesStr += ", "
		}
		servicesStr += fmt.Sprintf("%s (%d)", s.Service, s.Count)
	}
	fmt.Printf("Top services: %s\n", servicesStr)

	if len(r.AnalysisResults.LevelDistribution) > 0 {
		fmt.Println("\nLog Level Distribution:")
		levels := make([]struct {
			Level string
			Count int
		}, 0, len(r.AnalysisResults.LevelDistribution))
		for level, count := range r.AnalysisResults.LevelDistribution {
			levels = append(levels, struct {
				Level string
				Count int
			}{Level: level, Count: count})
		}
		sort.Slice(levels, func(i, j int) bool {
			return levels[i].Count > levels[j].Count
		})
		for _, level := range levels {
			fmt.Printf("  %s: %d\n", level.Level, level.Count)
		}
	}

	for _, plugin := range r.Plugins {
		results := plugin.GetResults()
		if len(results) > 0 {
			fmt.Printf("\nPlugin: %T\n", plugin)
			for k, v := range results {
				fmt.Printf("  %s: %v\n", k, v)
			}
		}
	}
}

func (r *RSyslogAnalyzer) displayTextSummary() {
	fmt.Println("\nSummary:")
	fmt.Printf("  Total entries: %d\n", r.AnalysisResults.TotalEntries)
	fmt.Printf("  Unique services: %d\n", len(r.AnalysisResults.UniqueServices))
	fmt.Printf("  Date range: %s to %s\n", r.AnalysisResults.DateRange[0], r.AnalysisResults.DateRange[1])
	fmt.Printf("  Days with logs: %d\n", len(r.Tree))
	fmt.Printf("  Error count: %d\n", r.AnalysisResults.ErrorCount)

	topServices := make([]struct {
		Service string
		Count   int
	}, 0, len(r.AnalysisResults.ServiceCounts))
	for service, count := range r.AnalysisResults.ServiceCounts {
		topServices = append(topServices, struct {
			Service string
			Count   int
		}{Service: service, Count: count})
	}
	sort.Slice(topServices, func(i, j int) bool {
		return topServices[i].Count > topServices[j].Count
	})
	if len(topServices) > 5 {
		topServices = topServices[:5]
	}
	servicesStr := ""
	for i, s := range topServices {
		if i > 0 {
			servicesStr += ", "
		}
		servicesStr += fmt.Sprintf("%s (%d)", s.Service, s.Count)
	}
	fmt.Printf("  Top services: %s\n", servicesStr)

	if len(r.AnalysisResults.LevelDistribution) > 0 {
		fmt.Println("  Level distribution:")
		for level, count := range r.AnalysisResults.LevelDistribution {
			fmt.Printf("    %s: %d\n", level, count)
		}
	}
}

func (r *RSyslogAnalyzer) ExportToJSON(filename string) error {
	parserInfo := r.Parser.GetParserInfo()

	exportData := map[string]interface{}{
		"metadata": map[string]interface{}{
			"exported_at":          time.Now().Format(time.RFC3339),
			"log_file":             r.LogFile,
			"analysis_period_days": r.Config.MaxDays,
			"parser_info":          parserInfo,
		},
		"summary": map[string]interface{}{
			"total_entries":   r.AnalysisResults.TotalEntries,
			"unique_services": len(r.AnalysisResults.UniqueServices),
			"date_range":      r.AnalysisResults.DateRange,
			"days_with_logs":  len(r.Tree),
			"error_count":     r.AnalysisResults.ErrorCount,
		},
		"service_stats":       r.AnalysisResults.ServiceCounts,
		"level_stats":         r.AnalysisResults.LevelDistribution,
		"hourly_distribution": r.AnalysisResults.HourlyDistribution,
	}

	pluginResults := make(map[string]interface{})
	for _, plugin := range r.Plugins {
		pluginResults[fmt.Sprintf("%T", plugin)] = plugin.GetResults()
	}
	exportData["plugin_results"] = pluginResults

	content, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, content, 0644)
}

func (r *RSyslogAnalyzer) ExportToCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"Timestamp", "Service", "Level", "Host", "PID", "Message"}); err != nil {
		return err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, dateServices := range r.Tree {
		for _, logs := range dateServices {
			for _, log := range logs {
				if err := writer.Write([]string{
					log.Timestamp.Format(time.RFC3339),
					log.Service,
					log.Level,
					log.Host,
					log.PID,
					log.Message,
				}); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (r *RSyslogAnalyzer) FindErrors(service string) []*LogEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	errors := make([]*LogEntry, 0)
	for _, dateServices := range r.Tree {
		for svc, logs := range dateServices {
			if service != "" && svc != service {
				continue
			}
			for _, log := range logs {
				if log.IsError() {
					errors = append(errors, log)
				}
			}
		}
	}

	sort.Slice(errors, func(i, j int) bool {
		return errors[i].Timestamp.Before(errors[j].Timestamp)
	})

	return errors
}

func (r *RSyslogAnalyzer) FilterLogs(servicePattern, level, messageContains string) []*LogEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	filtered := make([]*LogEntry, 0)
	var serviceRegex *regexp.Regexp
	if servicePattern != "" {
		serviceRegex = regexp.MustCompile(servicePattern)
	}

	for _, dateServices := range r.Tree {
		for service, logs := range dateServices {
			if serviceRegex != nil && !serviceRegex.MatchString(service) {
				continue
			}
			for _, log := range logs {
				if level != "" && log.Level != level {
					continue
				}
				if messageContains != "" && !strings.Contains(strings.ToLower(log.Message), strings.ToLower(messageContains)) {
					continue
				}
				filtered = append(filtered, log)
			}
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.Before(filtered[j].Timestamp)
	})

	return filtered
}

func main() {
	var (
		logFile            = flag.String("log-file", "", "Path to the syslog file (overrides default search).")
		maxDays            = flag.Int("max-days", 30, "Maximum days of logs to keep (default: 30).")
		truncateLength     = flag.Int("truncate-length", 80, "Length to truncate messages (default: 80).")
		showFullLines      = flag.Bool("show-full-lines", false, "Show full log messages without truncation.")
		wrapLines          = flag.Bool("wrap-lines", false, "Wrap long messages across lines.")
		maxLinesPerService = flag.Int("max-lines-per-service", 5, "Maximum lines to show per service (default: 5).")
		noColor            = flag.Bool("no-color", false, "Disable colored output.")
		verbose            = flag.Bool("verbose", false, "Enable verbose output.")
		summary            = flag.Bool("summary", false, "Show summary statistics.")
		systemInfo         = flag.Bool("system-info", false, "Display system and parser information.")
		enableAnalysis     = flag.Bool("enable-analysis", false, "Enable detailed log analysis.")
		export             = flag.String("export", "", "Export analysis results to JSON file.")
		exportCSV          = flag.String("export-csv", "", "Export log data to CSV file.")
		findErrors         = flag.Bool("find-errors", false, "Find and display error logs.")
		service            = flag.String("service", "", "Filter by specific service name.")
		filterService      = flag.String("filter-service", "", "Filter by service name pattern (regex).")
		filterLevel        = flag.String("filter-level", "", "Filter by log level.")
		filterMessage      = flag.String("filter-message", "", "Filter by message content.")
		maxFileSize        = flag.Int("max-file-size", 100, "Maximum file size in MB (default: 100).")
		maxMemoryEntries   = flag.Int("max-memory-entries", 100000, "Maximum log entries to keep in memory (default: 100000).")
		noRSyslogDetection = flag.Bool("no-rsyslog-detection", false, "Disable rsyslog capability detection.")
		configFile         = flag.String("config-file", "", "Load configuration from JSON file.")
		showVersion        = flag.Bool("version", false, "Show version information.")
	)

	flag.Parse()

	if *showVersion {
		fmt.Println("RSyslogAnalyzer 4.0.0")
		return
	}

	config := NewDefaultConfig()
	if *configFile != "" {
		if err := config.FromFile(*configFile); err != nil {
			log.Printf("Error loading config file: %v", err)
		}
	} else {
		config.MaxDays = *maxDays
		config.TruncateLength = *truncateLength
		config.ShowFullLines = *showFullLines
		config.WrapLines = *wrapLines
		config.MaxLinesPerService = *maxLinesPerService
		config.ColorOutput = !*noColor
		config.Verbose = *verbose
		config.EnableAnalysis = *enableAnalysis || *summary || *export != ""
		config.MaxFileSizeMB = *maxFileSize
		config.MaxMemoryEntries = *maxMemoryEntries
		config.UseRSyslogDetection = !*noRSyslogDetection
	}

	analyzer := NewRSyslogAnalyzer(*logFile, config)

	if *systemInfo {
		analyzer.DisplaySystemInfo()
		return
	}

	if err := analyzer.LoadLogs(); err != nil {
		log.Fatalf("Failed to load logs: %v", err)
	}
	analyzer.BuildTree()

	if *findErrors {
		errors := analyzer.FindErrors(*service)
		if len(errors) > 0 {
			fmt.Printf("\nFound %d error logs:\n", len(errors))
			displayCount := len(errors)
			if displayCount > 10 {
				displayCount = 10
			}
			for _, err := range errors[len(errors)-displayCount:] {
				message := err.Message
				if len(message) > 100 {
					message = message[:100] + "..."
				}
				fmt.Printf("  %s [%s] %s\n", err.Timestamp.Format("2006-01-02 15:04:05"), err.Service, message)
			}
		} else {
			fmt.Println("No error logs found.")
		}
	} else if *filterService != "" || *filterLevel != "" || *filterMessage != "" {
		filtered := analyzer.FilterLogs(*filterService, *filterLevel, *filterMessage)
		if len(filtered) > 0 {
			fmt.Printf("\nFound %d matching logs:\n", len(filtered))
			displayCount := len(filtered)
			if displayCount > 20 {
				displayCount = 20
			}
			for _, log := range filtered[len(filtered)-displayCount:] {
				message := log.Message
				if len(message) > 80 {
					message = message[:80] + "..."
				}
				level := log.Level
				if level == "" {
					level = "N/A"
				}
				fmt.Printf("  %s [%s] %s: %s\n", log.Timestamp.Format("2006-01-02 15:04:05"), log.Service, level, message)
			}
		} else {
			fmt.Println("No matching logs found.")
		}
	} else if *summary {
		analyzer.DisplaySummary()
	} else {
		analyzer.DisplayTree()
	}

	if *export != "" {
		if err := analyzer.ExportToJSON(*export); err != nil {
			log.Printf("Error exporting to JSON: %v", err)
		} else {
			log.Printf("Exported analysis to %s", *export)
		}
	}

	if *exportCSV != "" {
		if err := analyzer.ExportToCSV(*exportCSV); err != nil {
			log.Printf("Error exporting to CSV: %v", err)
		} else {
			log.Printf("Exported log data to %s", *exportCSV)
		}
	}
}
