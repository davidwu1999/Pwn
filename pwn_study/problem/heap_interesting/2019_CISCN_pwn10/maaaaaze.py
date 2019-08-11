#!/usr/bin/python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from hashlib import md5

length = 100
width = 100
maze = [[[1, 1, 1, 1] for j in range(width)] for i in range(length)]
visited = [[0 for j in range(width)] for i in range(length)]
mlength = 0
mnode = (0, 0)


def dfs(i, j, depth):
    global mlength
    # print (i,j)
    # print maze[i][j]
    visited[i][j] = 1
    # print [visited[i-1][j], visited[i][j+1], visited[i-1][j], visited[i][j-1]]
    while True:
        test = 0
        ti = 0
        tj = 0
        if maze[i][j][0] and not visited[i - 1][j]:
            test += 1
            ti = -1
        if maze[i][j][1] and not visited[i][j + 1]:
            test += 1
            tj = 1
        if maze[i][j][2] and not visited[i + 1][j]:
            test += 1
            ti = 1
        if maze[i][j][3] and not visited[i][j - 1]:
            test += 1
            tj = -1
        if test == 1:
            i += ti
            j += tj
            depth += 1
            visited[i][j] = 1
        else:
            break

    if depth > mlength:
        global mnode
        mlength = depth
        mnode = (i, j)
    if maze[i][j][0] and not visited[i - 1][j]:
        dfs(i - 1, j, depth + 1)
    if maze[i][j][1] and not visited[i][j + 1]:
        dfs(i, j + 1, depth + 1)
    if maze[i][j][2] and not visited[i + 1][j]:
        dfs(i + 1, j, depth + 1)
    if maze[i][j][3] and not visited[i][j - 1]:
        dfs(i, j - 1, depth + 1)


if __name__ == '__main__':
    sourse = open('./Maze.html').read()
    soup = BeautifulSoup(sourse, "html.parser")
    result = soup.select('td')
    # print result
    style = [i.get("style") for i in result]
    print style
    for i in range(length):
        for j in range(width):
            k = i * width + j
            if k > len(style):
                break
            walls = style[k]
            if u'border-top' in walls:
                maze[i][j][0] = 0
            if u'border-right' in walls:
                maze[i][j][1] = 0
            if u'border-bottom' in walls:
                maze[i][j][2] = 0
            if u'border-left' in walls:
                maze[i][j][3] = 0

    # print maze
    dfs(0, 0, 1)
    print mlength
    print mnode
    # print visited
    visited = [[0 for j in range(width)] for i in range(length)]
    dfs(mnode[0], mnode[1], 1)
    print mlength,"sctf{"+md5(str(mlength)).hexdigest()+"}"
    print mnode