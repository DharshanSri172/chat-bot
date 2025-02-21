import os
import shutil
import pyclamd
import streamlit as st
import time

# Function to connect to ClamAV and scan a file
def scan_with_clamav(file_path):
    try:
        cd = pyclamd.ClamdUnixSocket()
        cd.ping()  # Check if ClamAV is running
        result = cd.scan_file(file_path)
        if result is not None:
            return result[0]  # Malware detected, return result
        return None  # No malware
    except pyclamd.ClamdConnectionError:
        return "ClamAV connection error"
    except Exception as e:
        return f"Error: {e}"

# Function to quarantine malware
def quarantine_malware(file_path, quarantine_dir):
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    try:
        file_name = os.path.basename(file_path)
        quarantine_path = os.path.join(quarantine_dir, file_name)
        shutil.move(file_path, quarantine_path)
        return quarantine_path  # Return path where malware was quarantined
    except Exception as e:
        return f"Error moving file to quarantine: {e}"

# Function to scan USB drive
def scan_usb_drive(usb_path, quarantine_dir):
    malware_files = []
    for root, dirs, files in os.walk(usb_path):
        for file in files:
            file_path = os.path.join(root, file)
            result = scan_with_clamav(file_path)
            if result:
                st.warning(f"Malware detected in: {file_path} - {result}")
                # Quarantine malware
                quarantine_path = quarantine_malware(file_path, quarantine_dir)
                malware_files.append((file_path, quarantine_path))
    return malware_files

# Streamlit UI
def main():
    st.title("USB Malware Scanner")

    # Display a description
    st.write("This app scans USB drives for malware and quarantines infected files.")

    # Input for selecting USB drive mount point (Windows or Linux path)
    usb_path = st.text_input("Enter the path to the USB drive", "/media/usb")

    # Input for quarantine folder path
    quarantine_dir = st.text_input("Enter quarantine folder path", "./quarantine")

    if st.button("Scan USB Drive"):
        if not usb_path or not os.path.exists(usb_path):
            st.error("The USB path is invalid or does not exist.")
        else:
            st.write("Scanning in progress... Please wait.")
            with st.spinner("Scanning..."):
                # Scan the USB drive for malware
                malware_files = scan_usb_drive(usb_path, quarantine_dir)
                if malware_files:
                    st.success("Malware detected and quarantined.")
                    for original, quarantined in malware_files:
                        st.write(f"Malware file: {original} quarantined at {quarantined}")
                else:
                    st.success("No malware detected.")

if __name__ == "__main__":
    main()
