#!/bin/bash

# GhidraGPT Plugin Installation Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_instruction() {
    echo -e "${BLUE}[INSTRUCTION]${NC} $1"
}

# Help function
show_help() {
    echo "GhidraGPT Plugin Installation Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --auto       Automatically copy to Ghidra extensions directory"
    echo "  --manual     Show manual installation instructions"
    echo "  --help       Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  GHIDRA_INSTALL_DIR    Path to Ghidra installation (optional)"
    echo ""
}

# Find the plugin file
find_plugin_file() {
    local plugin_file=""
    local search_dirs="build/libs build/distributions"
    
    for dir in $search_dirs; do
        if [ -d "$dir" ]; then
            plugin_file=$(find "$dir" -name "*.zip" | head -1)
            if [ -n "$plugin_file" ]; then
                echo "$plugin_file"
                return 0
            fi
        fi
    done
    
    # If no zip found, look for JAR file
    for dir in $search_dirs; do
        if [ -d "$dir" ]; then
            plugin_file=$(find "$dir" -name "*.jar" | head -1)
            if [ -n "$plugin_file" ]; then
                echo "$plugin_file"
                return 0
            fi
        fi
    done
    
    return 1
}

# Auto installation function
auto_install() {
    local plugin_file="$1"
    
    print_status "Attempting automatic installation..."
    
    # Check for Ghidra user extensions directory in multiple locations
    local ghidra_user_dir=""
    
    # Check new location first (.config/ghidra)
    if [ -d "$HOME/.config/ghidra" ]; then
        ghidra_user_dir="$HOME/.config/ghidra"
    # Fallback to old location (.ghidra)
    elif [ -d "$HOME/.ghidra" ]; then
        ghidra_user_dir="$HOME/.ghidra"
    fi
    
    if [ -z "$ghidra_user_dir" ]; then
        print_error "Ghidra user directory not found at: $HOME/.config/ghidra or $HOME/.ghidra"
        print_status "Please run Ghidra at least once to create the user directory"
        return 1
    fi
    
    print_status "Found Ghidra user directory: $ghidra_user_dir"
    
    # Find the most recent Ghidra user directory (look for both patterns)
    local latest_ghidra_dir=""
    if [ -d "$ghidra_user_dir" ]; then
        # Look for .ghidra-* pattern (old style) or ghidra_*_DEV pattern (new style)
        latest_ghidra_dir=$(find "$ghidra_user_dir" -maxdepth 1 \( -name ".ghidra-*" -o -name "ghidra_*_DEV" \) -type d | sort -V | tail -1)
    fi
    
    if [ -z "$latest_ghidra_dir" ]; then
        print_warning "No Ghidra version directory found in $ghidra_user_dir"
        
        # Try to detect Ghidra version and create directory
        local ghidra_version=""
        if [ -n "$GHIDRA_INSTALL_DIR" ] && [ -f "$GHIDRA_INSTALL_DIR/Ghidra/application.properties" ]; then
            ghidra_version=$(grep "application.version=" "$GHIDRA_INSTALL_DIR/Ghidra/application.properties" 2>/dev/null | cut -d'=' -f2)
        fi
        
        if [ -n "$ghidra_version" ]; then
            print_status "Detected Ghidra version: $ghidra_version"
            latest_ghidra_dir="$ghidra_user_dir/.ghidra-$ghidra_version"
            print_status "Creating Ghidra user directory: $latest_ghidra_dir"
            mkdir -p "$latest_ghidra_dir"
        else
            print_error "Could not determine Ghidra version"
            print_status "Available directories:"
            ls -la "$ghidra_user_dir" || true
            return 1
        fi
    fi
    
    local extensions_dir="$latest_ghidra_dir/Extensions"
    
    print_status "Found/Created Ghidra user directory: $latest_ghidra_dir"
    print_status "Extensions directory: $extensions_dir"
    
    # Create extensions directory if it doesn't exist
    mkdir -p "$extensions_dir"
    
    # Get the plugin name (the directory name inside the zip, which is just "GhidraGPT")
    local plugin_dir_name="GhidraGPT"
    local dest_dir="$extensions_dir/$plugin_dir_name"
    
    # Remove existing version if present
    if [ -d "$dest_dir" ]; then
        print_warning "Existing plugin found, removing: $dest_dir"
        rm -rf "$dest_dir"
    fi
    if [ -f "$extensions_dir/$(basename "$plugin_file")" ]; then
        print_warning "Removing old zip file: $extensions_dir/$(basename "$plugin_file")"
        rm -f "$extensions_dir/$(basename "$plugin_file")"
    fi
    
    # Extract plugin to extensions directory
    print_status "Extracting plugin to: $dest_dir"
    unzip -q "$plugin_file" -d "$extensions_dir"
    
    if [ $? -eq 0 ] && [ -d "$dest_dir" ]; then
        print_status "✅ Plugin successfully installed to: $dest_dir"
        print_status ""
        print_instruction "Next steps:"
        print_instruction "1. Start/Restart Ghidra"
        print_instruction "2. Go to File → Configure"
        print_instruction "3. Find 'GhidraGPT' in the plugin list"
        print_instruction "4. Check the box to enable it"
        print_instruction "5. Click OK and restart Ghidra if prompted"
        return 0
    else
        print_error "Failed to extract plugin file"
        return 1
    fi
}

# Manual installation instructions
manual_install() {
    local plugin_file="$1"
    
    print_instruction "Manual Installation Instructions:"
    print_instruction ""
    print_instruction "1. Open Ghidra"
    print_instruction "2. Go to File → Install Extensions"
    print_instruction "3. Click the green '+' button"
    print_instruction "4. Navigate to and select: $plugin_file"
    print_instruction "5. Click OK to install"
    print_instruction "6. Restart Ghidra when prompted"
    print_instruction "7. Go to File → Configure"
    print_instruction "8. Find 'GhidraGPT' in the plugin list and enable it"
    print_instruction ""
    print_status "Plugin file location: $(realpath "$plugin_file")"
}

# List Ghidra installations
list_ghidra_info() {
    print_status "Ghidra Information:"
    
    # Check environment variable
    if [ -n "$GHIDRA_INSTALL_DIR" ]; then
        print_status "GHIDRA_INSTALL_DIR: $GHIDRA_INSTALL_DIR"
    fi
    
    # Check user directory (both locations)
    local ghidra_user_dir=""
    if [ -d "$HOME/.config/ghidra" ]; then
        ghidra_user_dir="$HOME/.config/ghidra"
    elif [ -d "$HOME/.ghidra" ]; then
        ghidra_user_dir="$HOME/.ghidra"
    fi
    
    if [ -n "$ghidra_user_dir" ]; then
        print_status "Ghidra user directory: $ghidra_user_dir"
        print_status "Available versions:"
        find "$ghidra_user_dir" -maxdepth 1 \( -name ".ghidra-*" -o -name "ghidra_*_DEV" \) -type d | sort -V | while read dir; do
            echo "  - $(basename "$dir")"
        done
    else
        print_warning "Ghidra user directory not found. Run Ghidra at least once."
    fi
    
    print_status ""
}

# Main execution
main() {
    local mode="auto"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --auto)
                mode="auto"
                shift
                ;;
            --manual)
                mode="manual"
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    print_status "GhidraGPT Plugin Installer"
    print_status "=========================="
    print_status ""
    
    # Show Ghidra info
    list_ghidra_info
    
    # Find the plugin file
    local plugin_file
    plugin_file=$(find_plugin_file)
    
    if [ $? -ne 0 ] || [ -z "$plugin_file" ]; then
        print_error "No plugin file found!"
        print_status "Please run './build.sh' first to build the plugin"
        exit 1
    fi
    
    print_status "Found plugin file: $plugin_file"
    print_status ""
    
    # Execute based on mode
    case $mode in
        auto)
            if auto_install "$plugin_file"; then
                print_status "✅ Installation completed successfully!"
            else
                print_error "❌ Automatic installation failed"
                print_status ""
                print_status "Falling back to manual installation instructions:"
                manual_install "$plugin_file"
                exit 1
            fi
            ;;
        manual)
            manual_install "$plugin_file"
            ;;
    esac
}

# Run main function with all arguments
main "$@"
