#!/usr/bin/env python3
"""
BJDCTF 2nd - 老文盲了
题目密文: 罼雧締眔擴灝淛匶襫黼瀬鎶軄鶛驕鳓哵眔鞹鰝
解题方法: 每个生僻字的拼音首字母拼成答案
  - 罼雧締 → BJD (flag格式前缀)
  - 眔擴灝 → dakuohao → 大括号 {
  - 淛匶襫黼瀬鎶軄鶛驕鳓哵 → flag内容
  - 眔鞹鰝 → dakuohao → 大括号 }
"""

# 手动建立生僻字→拼音映射（只有20个字，无需第三方库）
HANZI_PINYIN = {
    '罼': 'bi',
    '雧': 'ji',
    '締': 'di',
    '眔': 'da',
    '擴': 'kuo',
    '灝': 'hao',
    '淛': 'zhe',
    '匶': 'jiu',
    '襫': 'shi',
    '黼': 'fu',
    '瀬': 'lai',
    '鎶': 'ge',
    '軄': 'zhi',
    '鶛': 'jie',
    '驕': 'jiao',
    '鳓': 'le',
    '哵': 'ba',
    '鞹': 'kuo',
    '鰝': 'hao',
}

CIPHERTEXT = '罼雧締眔擴灝淛匶襫黼瀬鎶軄鶛驕鳓哵眔鞹鰝'


def get_pinyin_initials(text):
    """提取每个字的拼音首字母"""
    initials = []
    for ch in text:
        pinyin = HANZI_PINYIN.get(ch, '?')
        initials.append(pinyin[0].lower())
    return ''.join(initials)


def get_full_pinyin(text):
    """获取每个字的完整拼音"""
    return [HANZI_PINYIN.get(ch, '?') for ch in text]


def solve():
    print(f'密文: {CIPHERTEXT}')
    print(f'字数: {len(CIPHERTEXT)}')
    print()

    # Step 1: 获取每个字的拼音
    pinyins = get_full_pinyin(CIPHERTEXT)
    print('[1] 每个字的拼音:')
    for ch, py in zip(CIPHERTEXT, pinyins):
        print(f'    {ch} → {py}')
    print()

    # Step 2: 拼音首字母序列
    initials = get_pinyin_initials(CIPHERTEXT)
    print(f'[2] 拼音首字母序列: {initials}')
    print()

    # Step 3: 分组解读
    # 罼(=B)雧(=J)締(=D) → BJD (flag格式)
    # 眔(da)擴(kuo)灝(hao) → dakuohao = 大括号 {
    # 淛匶襫黼瀬鎶軄鶛驕鳓哵 → zhe jiu shi flag  lai ge zhi jie jiao le ba
    # 眔(da)鞹(kuo)鰝(hao) → dakuohao = 大括号 }

    # 分组提取flag内容（大括号之间的字）
    # 索引0-2: 罼雧締 → BJD (flag格式前缀)
    # 索引3-5: 眔擴灝 → da-kuo-hao → 大括号 {
    # 索引6-16: 淛匶襫黼瀬鎶軄鶛驕鳓哵 → flag内容 (11个字)
    # 索引17-19: 眔鞹鰝 → da-kuo-hao → 大括号 }

    flag_content_chars = CIPHERTEXT[6:17]  # 淛匶襫黼瀬鎶軄鶛驕鳓哵
    flag_content_pinyin = get_full_pinyin(flag_content_chars)

    print('[3] 分组解读:')
    print(f'    罼雧締 (索引0-2) → BJD (flag格式前缀)')
    print(f'    眔擴灝 (索引3-5) → da-kuo-hao → 大括号 {{')
    print(f'    flag内容 (索引6-16) → {" ".join(flag_content_pinyin)}')
    print(f'    眔鞹鰝 (索引17-19) → da-kuo-hao → 大括号 }}')
    print()

    # Step 4: 构造flag
    # flag内容直接复制生僻字本身
    flag = f'BJD{{{flag_content_chars}}}'
    print(f'[4] Flag (生僻字原文): {flag}')
    print()

    # 也可以用拼音首字母表示
    flag_initials = f'BJD{{{initials[6:17]}}}'
    print(f'[5] Flag (拼音首字母): {flag_initials}')
    print()

    # 拼音全拼表示
    flag_pinyin = 'BJD{' + '_'.join(flag_content_pinyin) + '}'
    print(f'[6] Flag (拼音全拼): {flag_pinyin}')

    return flag


if __name__ == '__main__':
    flag = solve()
    print()
    print(f'最终Flag: {flag}')
    print()
    print('注: 本题flag内容为生僻字原文，直接复制提交即可。')
    print('    拼音读法: zhe jiu shi fu lai ge zhi jie jiao le ba')
    print('    中文含义: 这就是flag直接交了吧')
