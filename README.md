# DXM-GlodFinger
DAEMON X MACHINA game cheating by Inexhaustible money

实现机甲战魔金币无消耗

最近对单机游戏修改器有点儿兴趣所以简单看了下，找了个最近玩的游戏练了练手，总的来说实现还是挺简单的，就是找到修改金币数值那段内存，然后再找到对这段内存进行修改的代码，给它置为nop就行了，第一次接触这些东西，会想起来好像也很久没在windows上写过代码了2333333，简单记了一下这个东西，整个过程大概是这样：

https://egguncle.github.io/2020/04/06/%E6%9C%BA%E7%94%B2%E6%88%98%E9%AD%94%E9%87%91%E5%B8%81%E6%97%A0%E6%B6%88%E8%80%97%E4%BF%AE%E6%94%B9%E5%99%A8%E5%BC%80%E5%8F%91%E7%AC%94%E8%AE%B0/#more

还是多多少少碰到了一点儿问题，没有深究一些问题出现的原因，总的来说还是以实现功能为导向。

还有就是用的时候，需要注意先将商店页面打开，这个游戏的商店有个单独的进程。

目前使用的开发环境为vs2019，朋友反映说没法用，我自己也试了试，使用x64-release的配置的时候是无法运行的，获取模块基址的时候就失败了，但是x64-debug是可以的，原因不是很清楚，需要尝试的话直接使用repo中的exe就行了。
