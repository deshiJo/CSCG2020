# Maze

## Tower

**Challenge**

Find a path to reach the tower and climb to the top.

See also: maze.liveoverflow.com


This is the second game challenge made by Liveoverflow.
This time we are a white rabbit in an online game and have to solve different challenges in a big maze.

**Solution**

The easiest Challegen was the **Tower** Challenge, where we just have to "solve" the maze and find a way to the big tower.

The first attempt was to use a flyhack to fly over the walls directly to the bit tower.
To do a simple fly hack, we have to find the characters y-coordination, which can be done by CheatEngine.
There are several tutorials, how to use **CheatEngine**. With this tool we can serach for values in the memory.
To find the y-coordination we have to use CheatEngine and search for unknown float values. CheatEngine can search for values or addresses in memory, by looking for increasing, decreasing and unchanged values.
So if we move our character a hill up and down, search for increased and decreased float values, we can decrease the number of possible memory addresses of the y-coordination.

When the y-coordination is found, we can lock the value and change it to a higher one to "fly".
unfortunately the server does not allow passing the walls, so we have to solve the maze manually. But with the fly hack, we have a good overview of the whole maze.

Just follow the paths until you reach the tower

(Image in the appendix)
![](writeupfiles/Tower/Tower.png)


## The Floor is Lava

**Challenge**

Reach the chest surrounded by dangerous lava.

See also: maze.liveoverflow.com

This is the second game challenge made by Liveoverflow.
This time we are a white rabbit in an online game and have to solve different challenges in a big maze.

**Solution**

If you follow the paths of the maze, you find a big lava lake with a small island and a chest in the middle.
To reach this island we have to fly over the lake. 

To do a simple fly hack, we have to find the characters y-coordination, which can be done by CheatEngine.
There are several tutorials, how to use **CheatEngine**. With this tool we can serach for values in the memory.
To find the y-coordination we have to use CheatEngine and search for unknown float values. CheatEngine can search for values or addresses in memory,by looking for increasing, decreasing and unchanged values.
So if we move our character a hill up and down, search for increased and decreased float values, we can decrease the number of possible memory addresses of the y-coordination.

When the y-coordination is found, we can lock the value and change it to a higher one to "fly".
unfortunately the server does not allow passing the walls, so we have to solve the maze manually. But with the fly hack, we have a good overview of the whole maze.

(image in the appendix)
![](writeupfiles/Lava/Lava.png)
