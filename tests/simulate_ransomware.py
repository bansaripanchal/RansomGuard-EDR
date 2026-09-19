import os
import time

def simulate():
    monitored_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "monitored_test")
    if not os.path.exists(monitored_dir):
        os.makedirs(monitored_dir)

    print(f"Starting simulation in {monitored_dir}")
    
    # 1. Mass create files (40 files)
    files = []
    for i in range(40):
        p = os.path.join(monitored_dir, f"sim_doc_{i}.txt")
        with open(p, "w") as f:
            f.write("standard documentation content data")
        files.append(p)
        
    print("Mass creation complete.")
    time.sleep(0.5)

    # 2. Mass rename files to suspicious extensions (40 renames)
    for p in files:
        dest = p + ".locked"
        if os.path.exists(p):
            os.rename(p, dest)
            
    print("Mass rename complete. Ransomware simulation finished.")

if __name__ == "__main__":
    simulate()
