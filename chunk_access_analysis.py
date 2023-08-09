import pandas as pd
df_num_access = pd.read_csv('summary.csv')
df_mmap = pd.read_csv('mmap_trace_mapped.csv')

#get the call stack column and remove the last part separated by :
df_mmap['call_stack_hexadecimal'] = df_mmap['call_stack_hexadecimal'].str.split(':').str[:-2]
#convert call_stack_hexadecimal column list to values
df_mmap['call_stack_hexadecimal'] = df_mmap['call_stack_hexadecimal'].apply(lambda x: ''.join(x))

#create a list of all unique call stack
unique_call_stack_hexadecimal = df_mmap['call_stack_hexadecimal'].unique().tolist()


#for each call stack, print the rows in df_mmap that matches the call stack and associate df_num_acess count column
for call_stack_hexadecimal in unique_call_stack_hexadecimal:
    df = df_mmap[df_mmap['call_stack_hexadecimal'] == call_stack_hexadecimal]
    #print("call_stack_hexadecimal ", call_stack_hexadecimal, ", number of mmaps ", len(df))
          
    #filter only size_allocation and call_stack_hash columns
    df = df[['size_allocation', 'call_stack_hash']]
    #merge df with df_num_access on call_stack_hash column
    df = df.merge(df_num_access, on='call_stack_hash')
    #remove repeted rows
    df = df.drop_duplicates()
    #check if df has more than one row
    if len(df) > 1:
        print(df)
        print('--------------------------------------------------------------\n')

    
    