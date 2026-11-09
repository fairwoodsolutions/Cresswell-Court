p=open('workers/admin/page.html').read()
a=open('workers/admin/worker.js').read()
esc=p.replace('\\','\\\\').replace('`','\\`').replace('${','\\${')
start=a.index('const PAGE = `')+len('const PAGE = `');i=start
while True:
    j=a.index('`;\n',i);k=j-1;c=0
    while a[k]=='\\': c+=1;k-=1
    if c%2==0: break
    i=j+1
open('workers/admin/worker.js','w').write(a[:start]+esc+a[j:])
