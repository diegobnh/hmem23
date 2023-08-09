import pandas as pd
import matplotlib.pyplot as plt

df_num_access = pd.read_csv('summary.csv')
df_mmap = pd.read_csv('mmap_trace_mapped.csv')

#get the call stack column and remove the last part separated by :
df_mmap['call_stack_hexadecimal_nochunk'] = df_mmap['call_stack_hexadecimal'].str.split(':').str[:-2]
#convert call_stack_hexadecimal column list to values
df_mmap['call_stack_hexadecimal_nochunk'] = df_mmap['call_stack_hexadecimal_nochunk'].apply(lambda x: ''.join(x))

#create a list of all unique call stack
unique_call_stack_hexadecimal = df_mmap['call_stack_hexadecimal_nochunk'].unique().tolist()


#for each call stack, print the rows in df_mmap that matches the call stack and associate df_num_acess count column
for call_stack_hexadecimal in unique_call_stack_hexadecimal:
    df = df_mmap[df_mmap['call_stack_hexadecimal_nochunk'] == call_stack_hexadecimal]
    #print("call_stack_hexadecimal ", call_stack_hexadecimal, ", number of mmaps ", len(df))
          
    #filter only size_allocation and call_stack_hash columns
    df = df[['size_allocation', 'call_stack_hash', 'call_stack_hexadecimal']]
    #merge df with df_num_access on call_stack_hash column
    df = df.merge(df_num_access, on='call_stack_hash')
    #remove repeted rows
    df = df.drop_duplicates()
    #check if df has more than one row and size_allocation from first row is bigger than specific value
    if len(df) > 1 and df.iloc[0]['size_allocation'] >= 1000001536:
        #plot the graph using bar plot with count column and axes x should be index column and save the plot in file pdf
        #rename x-axes string to be chunks name and y-axes to be number of access
        #title should be call_stack_hexadecimal from df and save the plot in file pdf
        #print(df)
        title = df.iloc[0]['call_stack_hexadecimal']
        title = title.split(':')[:-2]
        title = ':'.join(title)
        
        df.reset_index().plot.bar(x='index', y='count', rot=0, title=title, xlabel='Chunks', ylabel='Number of Access', legend=None)
        plt.savefig(call_stack_hexadecimal + '.pdf', bbox_inches="tight")
        plt.close()
    
        
        
    