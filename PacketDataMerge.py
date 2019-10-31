import EachMerge
import pyshark
from collections import Counter


def extrac_src(mininmum_PR, file_1, file_2, file_3):
    pb_filter = '(wlan.fc.type_subtype == 4)'
    packets_1 = pyshark.FileCapture(file_1, display_filter=pb_filter)
    packets_2 = pyshark.FileCapture(file_2, display_filter=pb_filter)
    packets_3 = pyshark.FileCapture(file_3, display_filter=pb_filter)

    wlan1_mac_list = [i.wlan.sa for i in packets_1]
    wlan2_mac_list = [i.wlan.sa for i in packets_2]
    wlan3_mac_list = [i.wlan.sa for i in packets_3]

    all_mac_list = wlan1_mac_list[:]
    all_mac_list.extend(wlan2_mac_list)
    all_mac_list.extend(wlan3_mac_list)

    all_count_dict = Counter(all_mac_list)
    wlan1_conunt_dict = Counter(wlan1_mac_list)
    wlan2_conunt_dict = Counter(wlan2_mac_list)
    wlan3_conunt_dict = Counter(wlan3_mac_list)

    master_mac_list = []
    for key in all_count_dict:
        if all_count_dict[key] >= mininmum_PR:
            if wlan1_conunt_dict[key] > 0 and wlan2_conunt_dict[key] > 0 and wlan3_conunt_dict[key] > 0:
                master_mac_list.append(key)

    packets_1.close()
    packets_2.close()
    packets_3.close()

    return master_mac_list


def every_src(mininmum_PR, file_1, file_2, file_3):
    pb_filter = '(wlan.fc.type_subtype == 4)'
    packets_1 = pyshark.FileCapture(file_1, display_filter=pb_filter)
    packets_2 = pyshark.FileCapture(file_2, display_filter=pb_filter)
    packets_3 = pyshark.FileCapture(file_3, display_filter=pb_filter)

    wlan1_mac_list = [i.wlan.sa for i in packets_1]
    print('# NIC_1\'s Probe Request Packet : ', len(wlan1_mac_list))
    wlan2_mac_list = [i.wlan.sa for i in packets_2]
    print('# NIC_2\'s Probe Request Packet : ', len(wlan2_mac_list))
    wlan3_mac_list = [i.wlan.sa for i in packets_3]
    print('# NIC_3\'s Probe Request Packet : ', len(wlan3_mac_list), '\n')

    all_mac_list = wlan1_mac_list[:]
    all_mac_list.extend(wlan2_mac_list)
    all_mac_list.extend(wlan3_mac_list)

    all_count_dict = Counter(all_mac_list)
    wlan1_conunt_dict = Counter(wlan1_mac_list)
    wlan2_conunt_dict = Counter(wlan2_mac_list)
    wlan3_conunt_dict = Counter(wlan3_mac_list)

    master_mac_list = []
    for key in all_count_dict:
        if all_count_dict[key] >= mininmum_PR:
            if wlan1_conunt_dict[key] > 0 and wlan2_conunt_dict[key] > 0 and wlan3_conunt_dict[key] > 0:
                tmp_count_list = [wlan1_conunt_dict[key], wlan2_conunt_dict[key], wlan3_conunt_dict[key]]
                master_mac_list.append([key, tmp_count_list])

    packets_1.close()
    packets_2.close()
    packets_3.close()

    print('# Device : ', len(master_mac_list))

    return master_mac_list


def start_merge(mininmum_PR, file1, file2, file3):
    print("... Start merging packets ...\n")

    file_list = [file1, file2, file3]
    src_list = every_src(mininmum_PR, file_list)
    # src_list = [['98:3b:8f:bb:21:d2', [105, 105, 106]], ['d4:6d:6d:40:7e:a5', [57, 66, 60]], ['f8:e6:1a:c9:cd:07', [303, 325, 322]], ['ac:ee:9e:e1:36:a7', [121, 69, 99]], ['f0:18:98:ac:84:a9', [34, 34, 32]],
    # ['10:02:b5:a0:61:67', [101, 118, 111]], ['30:10:b3:67:65:c7', [164, 167, 193]], ['08:ae:d6:0f:e9:4f', [129, 141, 137]], ['22:10:b3:67:65:c7', [55, 58, 72]], ['b8:27:eb:fc:13:6e', [48, 39, 37]],
    # ['08:ae:d6:e7:67:33', [168, 6, 138]], ['38:f9:d3:e8:0c:2b', [73, 78, 169]], ['60:fb:42:4c:52:9e', [699, 510, 864]], ['08:ae:d6:23:d6:cd', [61, 65, 64]], ['08:e6:89:f2:b8:b1', [111, 36, 72]],
    # ['a4:84:31:f5:ca:06', [86, 42, 95]], ['94:8b:c1:8d:a8:12', [57, 53, 52]], ['38:f9:d3:9c:35:5a', [57, 45, 45]], ['34:e1:2d:c5:ed:38', [38, 31, 43]], ['18:56:80:a4:59:66', [40, 40, 42]],
    # ['54:99:63:7d:b1:27', [163, 165, 158]], ['a8:2b:b9:52:40:4a', [75, 71, 74]], ['18:56:80:69:41:19', [42, 15, 58]], ['f8:e6:1a:ba:a4:8a', [70, 10, 71]], ['84:2e:27:84:4b:37', [64, 10, 38]],
    # ['b0:6f:e0:27:db:5c', [82, 115, 128]], ['50:77:05:00:21:c3', [76, 69, 73]], ['88:9f:6f:4f:63:ac', [43, 20, 39]], ['94:8b:c1:dc:ed:ea', [45, 37, 35]], ['00:57:c1:c4:72:c4', [43, 42, 46]],
    # ['24:4b:81:b6:48:ba', [140, 129, 131]], ['e8:3a:12:0e:61:8d', [57, 41, 45]], ['24:f5:aa:b1:07:ff', [38, 12, 60]], ['58:00:e3:ab:26:f5', [36, 36, 34]]]

    master_list = []
    for mac, count_list in src_list:
        print('========================================')
        print('Target Device : ', mac, '\n')
        for i in range(3):
            print('# NIC_', i+1, '\'s Target device\'s Packet : ', count_list[i])
        print('Now mergeing target device .... ', end='')
        tmp_merged = EachMerge.main(file_list, mac, count_list)
        print('!\n')
        print('# Merged Packet : ', len(tmp_merged))
        master_list.append(tmp_merged)
        del tmp_merged
        print('========================================\n')

    print('... End merging packets ...')
    return master_list
