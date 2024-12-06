#!/usr/bin/env python
# coding: utf-8

# In[50]:


#import libraries
import re
import csv


# In[51]:


from collections import Counter


# In[ ]:


#read log file


# In[31]:


file = "sample.log"
with open(file,'r') as file:
    lines = file.readlines()


# ## (1) Count requests per IP Address

# In[ ]:


#extract ip addresses using regrex


# In[32]:


ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'


# In[52]:


ip_addresses = [re.search(ip_pattern,i).group() for i in lines if re.search(ip_pattern,i)]


# In[53]:


#count the request per ip address


# In[54]:


ip_count = Counter(ip_addresses)


# In[ ]:


#sorting and printing results


# In[55]:


sorted_counts = sorted(ip_count.items(),key = lambda x: x[1],reverse=True)


# In[56]:


print(f"{'IP Address':<20}{'Request Count'}")
print("=" * 30)
for ip,count in sorted_counts:
    print(f"{ip:<20} {count}")


# In[ ]:





# ## (2) identifying most frequently accessed endpoints

# In[40]:


#extract endpoints using regrex
endpoint_pattern = r'\"[A-Z]+\s(/[\w\-/.]*)'
end_points = [re.search(endpoint_pattern,i).group(1) for i in lines if re.search(endpoint_pattern,i)]


# In[41]:


#count endpoint access
end_points_count = Counter(end_points)


# In[42]:


#find most frequently accessed endpoints
most_accessed = end_points_count.most_common(1)[0]


# In[43]:


#result print
print(f"Most frequently accessed endpoints: {most_accessed[0]}")
print(f"Accessed Count: {most_accessed[1]}")


# ## Detect suspicious activity

# In[44]:


threshold = 10


# In[ ]:


#log entries with HTTP status code 401 or message "Invalid credentials"


# In[ ]:


failed_login_pattern = r'\b401\b|Invalid credentials'


# In[45]:


failed_ip = [
    re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',i).group()
    for i in lines if re.search(failed_login_pattern,i)
]


# In[ ]:


#count failed ligin attempts per ip


# In[46]:


failed_counts = Counter(failed_ip)


# In[ ]:


#ip exceeding threshold


# In[47]:


suspicious_ip = {ip: count for ip,count in failed_counts.items() if count > threshold}


# In[ ]:


#print results


# In[48]:


if suspicious_ip:
    print(f"Suspicious IPs with more than {threshold} failed login attempts.")
    print(f"{'IP Address':<20} {'Failed Attempts'}")
    print("=" * 40)
    for ip,count in suspicious_ip.items():
        print(f"{ip:<20} {count}")
else:
    print(f"No IPs exceeded the threshold of {threshold} failed login attempts.")


# ## csv file

# In[49]:


with open("log_analysis_results.csv",'w',newline='') as csvfile:
    writer = csv.writer(csvfile)
    
    
    writer.writerow(["Requests Per IP"])
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in ip_count.items():
        writer.writerow([ip, count])
        
    writer.writerow([])
    
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint","Access Count"])
    writer.writerow(most_accessed)
    
    writer.writerow([])
    
    
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed LOgin Count"])
    for ip, count in suspicious_ip.items():
        writer.writerow([ip, count])
print("\nResults saved to 'log_analysis_results.csv'")

