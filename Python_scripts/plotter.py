import pandas as pd
import matplotlib.pyplot as plt
import math

def plot_column_distributions(file_path):
    df = pd.read_csv(file_path, sep=',', comment='#', header=None)

    df.columns = [f"Column_{i+1}" for i in range(df.shape[1])]
    
    num_columns = df.shape[1]
    print(f"Number of columns: {num_columns}")
    
    ncols = 3
    nrows = math.ceil(num_columns / ncols)
    
    fig, axes = plt.subplots(nrows=nrows, ncols=ncols, figsize=(15, nrows * 4))

    axes = axes.flatten()
    
    for i, ax in enumerate(axes[:num_columns]):  
        column_name = df.columns[i] 
        df[column_name].plot(kind='hist', bins=20, edgecolor='black', alpha=0.7, ax=ax)
        ax.set_title(f'Distribution of {column_name}')
        ax.set_xlabel('Value')
        ax.set_ylabel('Frequency')

    for j in range(num_columns, len(axes)):
        fig.delaxes(axes[j])

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    file_path = "tls_2013-06-18-Neutrino-EK-traffic.log"
    plot_column_distributions(file_path)
