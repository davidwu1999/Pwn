info = """                                            
 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
   x  x         x        xxx x       x   xx 
 x  x   xxxxxxx x xxxx x  x   x xx x  xx  x 
 xx   xx      x  x    xxx   x xx    x  xx x 
 xxxxx  xx xxx  xx xx  x x xx   x x  x  x x 
 xx    x   x   x   x x   x x  x x x x  x  x 
 x  xx   xx  xxx xx  xxx   x x  x x x xx xx 
 x x  x xx  xx   x x    xxx x  x xx x    xx 
 x   x  x  x   xx   x x x   x x     xx x  x 
 xxx  x   x  xx  xx    xx x   x x xx x  x x 
 x  x  xxxxx x x    x x   xxxx  x x   x  xx 
 x x x    x  x x xx x   xx   x x  xx x x  x 
 x   xx x  x x     x xxx   xx  x x      x x 
 x x  xx x x  x xx   x   x x  xx  xx xx x x 
 x  x    x  x xx  x x  x x  x x x  x   x  x 
 x xx xx x x    x x  xxx  xx  x xx x x  x x 
 x   x   x  x x x xx    x  x x   x x  x   x 
 x x  x x x  x  x  x xx xx   xxx x  xx  x x 
 x  x x x   x  x x  x    x x      x   xx xx 
 x x  xx  xx  x   x x x x   xxxxx  xx     x 
 x x x   xx x x x   x  x  xx     xxxx x x x 
 x x x x x    x xx x  x  xxx xxx   x   x  x 
 x x x  x  xxx    x  x x  x  x  xx xx x  xx 
 x x  x   x  x xx  x    xx  x  x x   x  x x 
 x xx  xx  x   x x  xxx  x x  x   xx  x   x 
 x  xx   x x xxx  x   xx   x x  x  xx xx xx 
 xx  x x  x  x   x xx  xxxx    x x  x     x 
 xxx x xx x xxx x   xx     x xx   x xxxx xx 
 xx  x  x x  x  x x   xx xxx    x x    x  x 
 x  x x  x x   x   xx  x    xxxx   xxx  x x 
 x x  xx    xx  xx  x x  xx x  x xx  x x  x 
 x  x   x x x x  xx x xxxx    x  x  x  x xx 
 xx x x x x    x  x x      xx x x  x x x  x 
 xx  xx x  xx x  x   x x xxx  x  x   x   xx 
 x x    xx x  x x xx x  x   x  x xxx  xxx x 
 x xx x  x  xx  x  x xx x x  xxx    x     x 
 x  xx x  x  x x x x  x x xx    xx x xxxx x 
 xx    xx  x   x x  x x x   xxx x  x    x x 
 x x xx   x xxx    x  xx  xx  x x x  xx   x 
 x    x xxx    x x  x  x x   x  x x x  xx x 
 x xx       xx    x  x     x  x      x      
 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
                                            """
print info
info2 = []
for i in info.split("\n"):
	info2.append(i)
info = info2
path = ""
width = 44
height = 44
targetx = 41
targety = 42
print len(info2)
print len(info2[0])
flag = [[0 for i in range(width)]for j in range(height)]
#print flag
path_cal = ""
def maze(x,y):
	#print x,y,y + 1 < width
	#print info[x]
	global path,flag,path_cal
	if x == targetx and y == targety:
		print path
		path = path_cal
		return True
	if x + 1 < height - 1 and info[x + 1][y] != "x" and flag[x + 1][y] == 0:
	#	print info[x + 1][y]
		path += "s"
		flag[x + 1][y] = 1
		maze(x + 1,y)
		flag[x + 1][y] = 0
		path = path[:-1]
	if x != 0 and info[x - 1][y] != "x" and flag[x - 1][y] == 0:
		path += "w"
		flag[x - 1][y] = 1
                maze(x - 1,y)
		flag[x - 1][y] = 0
                path = path[:-1]
	if y != 0 and info[x][y - 1] != "x" and flag[x][y - 1] == 0:
		path += "a"
		flag[x][y - 1] = 1
                maze(x,y - 1)
		flag[x][y - 1] = 0
                path = path[:-1]
	if y + 1 < width - 1 and info[x][y + 1] != "x" and flag[x][y + 1] == 0:
		path += "d"
		flag[x][y + 1] = 1
                maze(x,y + 1)
		flag[x][y + 1] = 0
                path = path[:-1]

def calcu(x,y,targetx,targety,info):
	maze(x,y)
calcu(x,y,targetx,targety,info)
#maze(2,1)
