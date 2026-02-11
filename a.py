#!/usr/bin/env python3
"""
File Permission Analyzer - Streamlit Web App
Easy-to-use web interface for checking file permissions.
"""

import streamlit as st
import os
import stat
import datetime

# Try to get user/group names (works on Mac/Linux)
try:
    import pwd
    import grp
    CAN_GET_NAMES = True
except:
    CAN_GET_NAMES = False


def analyze_file(file_path):
    """Analyze file permissions and return results."""
    
    # Fix Windows path issues
    file_path = file_path.strip()  # Remove extra spaces
    file_path = os.path.normpath(file_path)  # Normalize path separators
    
    # Check if file exists
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}
    
    try:
        # Get file info
        info = os.stat(file_path)
        mode = info.st_mode
        
        # Basic info
        results = {
            "path": file_path,
            "type": "Directory" if os.path.isdir(file_path) else "File",
            "size": info.st_size,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "octal": oct(stat.S_IMODE(mode)),
            "symbolic": stat.filemode(mode),
            "modified": datetime.datetime.fromtimestamp(info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        }
        
        # Get owner/group names
        if CAN_GET_NAMES:
            try:
                results["owner_name"] = pwd.getpwuid(info.st_uid).pw_name
                results["group_name"] = grp.getgrgid(info.st_gid).gr_name
            except:
                results["owner_name"] = "Unknown"
                results["group_name"] = "Unknown"
        else:
            results["owner_name"] = "N/A (Windows)"
            results["group_name"] = "N/A (Windows)"
        
        # Owner permissions
        results["owner_read"] = bool(mode & stat.S_IRUSR)
        results["owner_write"] = bool(mode & stat.S_IWUSR)
        results["owner_execute"] = bool(mode & stat.S_IXUSR)
        
        # Group permissions
        results["group_read"] = bool(mode & stat.S_IRGRP)
        results["group_write"] = bool(mode & stat.S_IWGRP)
        results["group_execute"] = bool(mode & stat.S_IXGRP)
        
        # Others permissions
        results["others_read"] = bool(mode & stat.S_IROTH)
        results["others_write"] = bool(mode & stat.S_IWOTH)
        results["others_execute"] = bool(mode & stat.S_IXOTH)
        
        # Special permissions
        results["setuid"] = bool(mode & stat.S_ISUID)
        results["setgid"] = bool(mode & stat.S_ISGID)
        results["sticky"] = bool(mode & stat.S_ISVTX)
        
        # Security warnings
        warnings = []
        if mode & stat.S_IWOTH:
            warnings.append("⚠️ Anyone can modify this file/directory!")
        if mode & stat.S_ISUID:
            warnings.append("⚠️ File runs with special owner privileges")
        if os.path.isdir(file_path) and (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
            warnings.append("⚠️ Unsafe directory permissions detected!")
        
        results["warnings"] = warnings
        
        return results
        
    except Exception as e:
        return {"error": f"Error analyzing file: {str(e)}"}


def format_permission_box(read, write, execute):
    """Format permission as rwx string."""
    return f"{'r' if read else '-'}{'w' if write else '-'}{'x' if execute else '-'}"


# Streamlit App Configuration
st.set_page_config(
    page_title="File Permission Analyzer",
    page_icon="🔐",
    layout="wide"
)

# Title and description
st.title("🔐 File Permission Analyzer")
st.markdown("Analyze file and directory permissions with detailed security checks")

# Sidebar
with st.sidebar:
    st.header("📖 About")
    st.info("""
    This tool analyzes file system permissions and provides:
    - Basic file information
    - Detailed permission breakdown
    - Security warnings
    - Owner and group details
    """)
    
    st.header("💡 How to Use")
    st.markdown("""
    1. Enter a file or directory path
    2. Click 'Analyze'
    3. View detailed permissions and security info
    """)
    
    st.header("📝 Examples")
    st.code("/etc/passwd")
    st.code("/tmp")
    st.code(".")
    if os.name == 'nt':
        st.code("C:\\Windows\\System32")

# Main content
tab1, tab2 = st.tabs(["📤 Upload File", "📂 Server Path (Advanced)"])

with tab1:
    st.header("Upload a File to Analyze")
    uploaded_file = st.file_uploader(
        "Choose a file",
        type=None,
        help="Upload any file to analyze its permissions"
    )
    
    if uploaded_file:
        # Save uploaded file temporarily
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=uploaded_file.name) as tmp_file:
            tmp_file.write(uploaded_file.getbuffer())
            file_path = tmp_file.name
        
        analyze_button = True
        st.success(f"✅ File uploaded: {uploaded_file.name}")
    else:
        analyze_button = False
        file_path = None

with tab2:
    st.header("Enter File Path (Server)")
    st.info("⚠️ This analyzes files on the server, not your local computer")
    
    # Input section
    col1, col2 = st.columns([4, 1])
    with col1:
        server_path = st.text_input(
            "File or Directory Path",
            value=".",
            placeholder="Enter path to file or directory",
            label_visibility="collapsed"
        )
    with col2:
        if st.button("🔍 Analyze", type="primary", use_container_width=True):
            file_path = server_path
            analyze_button = True

    # Quick access buttons
    st.markdown("**Quick Access:**")
    quick_col1, quick_col2, quick_col3, quick_col4 = st.columns(4)
    with quick_col1:
        if st.button("📂 Current Directory", use_container_width=True):
            file_path = "."
            analyze_button = True
    with quick_col2:
        if st.button("🏠 Home Directory", use_container_width=True):
            file_path = os.path.expanduser("~")
            analyze_button = True
    with quick_col3:
        if st.button("📁 /tmp", use_container_width=True):
            file_path = "/tmp"
            analyze_button = True
    with quick_col4:
        if st.button("📄 /etc/passwd", use_container_width=True):
            file_path = "/etc/passwd"
            analyze_button = True

st.divider()

# Analyze and display results
if analyze_button or file_path:
    results = analyze_file(file_path)
    
    if "error" in results:
        st.error(results["error"])
    else:
        # Basic Information Section
        st.header("📋 Basic Information")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Type", results["type"])
        with col2:
            size_kb = results["size"] / 1024
            size_display = f"{size_kb:.2f} KB" if size_kb > 1 else f"{results['size']} bytes"
            st.metric("Size", size_display)
        with col3:
            st.metric("Last Modified", results["modified"])
        
        # Owner Information
        st.header("👤 Ownership")
        col1, col2 = st.columns(2)
        
        with col1:
            st.info(f"**Owner:** {results['owner_name']} (UID: {results['uid']})")
        with col2:
            st.info(f"**Group:** {results['group_name']} (GID: {results['gid']})")
        
        # Permissions Section
        st.header("🔐 Permissions")
        
        # Show symbolic and octal
        perm_col1, perm_col2 = st.columns(2)
        with perm_col1:
            st.code(results["symbolic"], language=None)
        with perm_col2:
            st.code(results["octal"], language=None)
        
        # Permission breakdown table
        st.subheader("Permission Breakdown")
        
        col1, col2, col3, col4 = st.columns([2, 2, 2, 2])
        
        with col1:
            st.markdown("**Category**")
            st.write("Owner")
            st.write("Group")
            st.write("Others")
        
        with col2:
            st.markdown("**Read**")
            st.write("✅" if results["owner_read"] else "❌")
            st.write("✅" if results["group_read"] else "❌")
            st.write("✅" if results["others_read"] else "❌")
        
        with col3:
            st.markdown("**Write**")
            st.write("✅" if results["owner_write"] else "❌")
            st.write("✅" if results["group_write"] else "❌")
            st.write("✅" if results["others_write"] else "❌")
        
        with col4:
            st.markdown("**Execute**")
            st.write("✅" if results["owner_execute"] else "❌")
            st.write("✅" if results["group_execute"] else "❌")
            st.write("✅" if results["others_execute"] else "❌")
        
        # Special Permissions
        if results["setuid"] or results["setgid"] or results["sticky"]:
            st.subheader("⭐ Special Permissions")
            
            if results["setuid"]:
                st.warning("**Setuid:** File runs with owner's privileges")
            if results["setgid"]:
                st.warning("**Setgid:** File runs with group's privileges")
            if results["sticky"]:
                st.info("**Sticky Bit:** Only owner can delete files in directory")
        
        # Security Analysis
        st.header("🛡️ Security Analysis")
        
        if results["warnings"]:
            st.error("**Security Issues Found:**")
            for warning in results["warnings"]:
                st.warning(warning)
        else:
            st.success("✅ No security issues detected!")
        
        # Visual Permission Display
        st.header("📊 Visual Representation")
        
        vis_col1, vis_col2, vis_col3 = st.columns(3)
        
        with vis_col1:
            owner_perm = format_permission_box(
                results["owner_read"],
                results["owner_write"],
                results["owner_execute"]
            )
            st.markdown(f"""
            <div style='background-color: #e3f2fd; padding: 20px; border-radius: 10px; text-align: center;'>
                <h3 style='color: #1976d2;'>👤 Owner</h3>
                <h1 style='font-family: monospace; color: #0d47a1;'>{owner_perm}</h1>
            </div>
            """, unsafe_allow_html=True)
        
        with vis_col2:
            group_perm = format_permission_box(
                results["group_read"],
                results["group_write"],
                results["group_execute"]
            )
            st.markdown(f"""
            <div style='background-color: #f3e5f5; padding: 20px; border-radius: 10px; text-align: center;'>
                <h3 style='color: #7b1fa2;'>👥 Group</h3>
                <h1 style='font-family: monospace; color: #4a148c;'>{group_perm}</h1>
            </div>
            """, unsafe_allow_html=True)
        
        with vis_col3:
            others_perm = format_permission_box(
                results["others_read"],
                results["others_write"],
                results["others_execute"]
            )
            st.markdown(f"""
            <div style='background-color: #fff3e0; padding: 20px; border-radius: 10px; text-align: center;'>
                <h3 style='color: #e65100;'>🌐 Others</h3>
                <h1 style='font-family: monospace; color: #bf360c;'>{others_perm}</h1>
            </div>
            """, unsafe_allow_html=True)

# Footer
st.divider()
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>File Permission Analyzer | Built with Streamlit</p>
</div>
""", unsafe_allow_html=True)