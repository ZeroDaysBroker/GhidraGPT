package ghidragpt.utils;

import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.List;
import java.util.ArrayList;

/**
 * Utility class for applying GPT suggestions to Ghidra programs
 */
public class GPTSuggestionApplier {
    
    private static final Pattern VARIABLE_SUGGESTION_PATTERN = 
        Pattern.compile("([a-zA-Z_][a-zA-Z0-9_]*) -> ([a-zA-Z_][a-zA-Z0-9_]*):?(.*)");
    
    /**
     * Parse and apply variable naming suggestions from GPT
     */
    public static class VariableSuggestion {
        public final String oldName;
        public final String newName;
        public final String reason;
        
        public VariableSuggestion(String oldName, String newName, String reason) {
            this.oldName = oldName;
            this.newName = newName;
            this.reason = reason;
        }
    }
    
    /**
     * Parse variable suggestions from GPT response
     */
    public static List<VariableSuggestion> parseVariableSuggestions(String gptResponse) {
        List<VariableSuggestion> suggestions = new ArrayList<>();
        
        String[] lines = gptResponse.split("\\n");
        for (String line : lines) {
            Matcher matcher = VARIABLE_SUGGESTION_PATTERN.matcher(line.trim());
            if (matcher.matches()) {
                String oldName = matcher.group(1);
                String newName = matcher.group(2);
                String reason = matcher.groupCount() > 2 ? matcher.group(3).trim() : "";
                
                if (isValidVariableName(newName)) {
                    suggestions.add(new VariableSuggestion(oldName, newName, reason));
                }
            }
        }
        
        return suggestions;
    }
    
    /**
     * Apply variable suggestions to a function
     */
    public static int applyVariableSuggestions(Function function, List<VariableSuggestion> suggestions) {
        int appliedCount = 0;
        
        for (VariableSuggestion suggestion : suggestions) {
            try {
                // Try to find and rename local variables
                Variable[] localVars = function.getLocalVariables();
                for (Variable var : localVars) {
                    if (var.getName().equals(suggestion.oldName)) {
                        var.setName(suggestion.newName, var.getSource());
                        appliedCount++;
                        break;
                    }
                }
                
                // Try to find and rename parameters
                Parameter[] params = function.getParameters();
                for (Parameter param : params) {
                    if (param.getName().equals(suggestion.oldName)) {
                        param.setName(suggestion.newName, param.getSource());
                        appliedCount++;
                        break;
                    }
                }
                
            } catch (DuplicateNameException | InvalidInputException e) {
                // Skip this suggestion if name is invalid or duplicate
                System.err.println("Could not apply suggestion: " + suggestion.oldName + 
                                 " -> " + suggestion.newName + " (" + e.getMessage() + ")");
            }
        }
        
        return appliedCount;
    }
    
    /**
     * Validate if a string is a valid variable name
     */
    public static boolean isValidVariableName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        
        // Check if name starts with letter or underscore
        if (!Character.isLetter(name.charAt(0)) && name.charAt(0) != '_') {
            return false;
        }
        
        // Check if all characters are letters, digits, or underscores
        for (int i = 1; i < name.length(); i++) {
            char c = name.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '_') {
                return false;
            }
        }
        
        // Check against reserved keywords
        return !isReservedKeyword(name);
    }
    
    /**
     * Check if name is a reserved C keyword
     */
    private static boolean isReservedKeyword(String name) {
        String[] keywords = {
            "auto", "break", "case", "char", "const", "continue", "default", "do",
            "double", "else", "enum", "extern", "float", "for", "goto", "if",
            "int", "long", "register", "return", "short", "signed", "sizeof", "static",
            "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while"
        };
        
        for (String keyword : keywords) {
            if (keyword.equals(name)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Extract code blocks from GPT response (useful for rewritten code)
     */
    public static String extractCodeBlock(String gptResponse) {
        // Look for code blocks marked with ```c or ```
        Pattern codeBlockPattern = Pattern.compile("```(?:c)?\\s*\\n(.*?)\\n```", Pattern.DOTALL);
        Matcher matcher = codeBlockPattern.matcher(gptResponse);
        
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        // If no code block markers, try to extract C-like code
        String[] lines = gptResponse.split("\\n");
        StringBuilder codeBuilder = new StringBuilder();
        boolean inCode = false;
        
        for (String line : lines) {
            String trimmed = line.trim();
            
            // Start of code block indicators
            if (trimmed.contains("{") || trimmed.matches("^[a-zA-Z_][a-zA-Z0-9_]*\\s*\\(.*")) {
                inCode = true;
            }
            
            if (inCode) {
                codeBuilder.append(line).append("\\n");
            }
            
            // End of code block
            if (trimmed.equals("}") && inCode) {
                break;
            }
        }
        
        return codeBuilder.toString();
    }
    
    /**
     * Generate a summary report of applied suggestions
     */
    public static String generateSuggestionReport(Function function, List<VariableSuggestion> suggestions, int appliedCount) {
        StringBuilder report = new StringBuilder();
        report.append("GPT Suggestion Report for ").append(function.getName()).append("\\n");
        report.append("=".repeat(50)).append("\\n");
        report.append("Total suggestions: ").append(suggestions.size()).append("\\n");
        report.append("Successfully applied: ").append(appliedCount).append("\\n\\n");
        
        for (VariableSuggestion suggestion : suggestions) {
            report.append("• ").append(suggestion.oldName)
                  .append(" → ").append(suggestion.newName);
            if (!suggestion.reason.isEmpty()) {
                report.append(" (").append(suggestion.reason).append(")");
            }
            report.append("\\n");
        }
        
        return report.toString();
    }
}
