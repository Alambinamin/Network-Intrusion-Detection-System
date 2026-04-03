import pandas as pd
import matplotlib.pyplot as plt
import os


csv_file = 'nids_alerts.csv'


if not os.path.exists(csv_file) or os.stat(csv_file).st_size == 0:
    print(f"Error: {csv_file} is missing or empty. Run your NIDS and Attack script first!")
else:
    
    try:
    
        df = pd.read_csv(csv_file)
        
        
        if 'Service' not in df.columns:
            print("Header missing in CSV. Manually assigning column names...")
            
            df = pd.read_csv(csv_file, names=['Timestamp', 'Source_IP', 'Service', 'Confidence'])

        
        attack_counts = df['Service'].value_counts()

        
        plt.figure(figsize=(10, 6))
        attack_counts.plot(kind='bar', color='firebrick')
        
        plt.title('NIDS Detection Report: Attacks by Service Type')
        plt.xlabel('Service (Port)')
        plt.ylabel('Number of Alerts')
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        
        plt.tight_layout()
        plt.savefig('nids_report_chart.png') # This saves it as an image for your report
        print("Success! Chart saved as 'nids_report_chart.png'")
        
        
        try:
            plt.show()
        except Exception:
            print("Note: Could not open a window, but the image was saved successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")
