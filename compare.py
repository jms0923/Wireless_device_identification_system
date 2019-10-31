import pyshark
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from sklearn.cluster import *
from sklearn.utils.testing import ignore_warnings

numOfCluster = 4
numOfIB = 100  # number of inter burst packet in one feature
source = '40:9c:28:47:a0:6d'  # target device
originFeatureList = []
probeRequest_filter = 'wlan.fc.type_subtype == 4'

cap = pyshark.FileCapture('./data/20190719_1.pcapng', display_filter=probeRequest_filter)





previousPacketTime = cap[0].sniff_time
nowPacketTime = cap[0].sniff_time

## 시간 초기화 ##
initTime = previousPacketTime - nowPacketTime
stackTime = initTime
previousPacketTime = initTime
nowPacketTime = initTime

# get euclidean distance from two point
def euclidean(originFeature, newFeature):
    eachDistance = 0.0
    sum = 0.0

    for i in range(len(originFeature)):
        for j in range(2):
            # 차의 제곱을 더함
            eachDistance += (originFeature[i][j] - newFeature[i][j]) ** 2
        # 루트 취한걸 다 더함
        sum += (eachDistance ** 0.5)
    return sum

## 패킷 도착시간 차이의 누적 ##
def 
someIntel = source
listStackTime = []
numOfStack = 0

for packet in cap:
    if packet['WLAN'].sa == someIntel:
        nowPacketTime = packet.sniff_time

        if previousPacketTime:
            stackTime += (nowPacketTime - previousPacketTime)
            numOfStack += 1
            tmp = str(stackTime).split(':')
            tmpTime = tmp[0] + tmp[1] + tmp[2].split('.')[0] + tmp[2].split('.')[1]
            listStackTime.append(int(tmpTime))
            previousPacketTime = nowPacketTime

        else:
            previousPacketTime = packet.sniff_time

plot_x = [x for x in range(numOfStack)]
plot_y = [y for y in listStackTime]
plt.plot(plot_x, plot_y)
plt.show()

# %%
## InterBurst ##
interBurst = []  # [0] -> control sample -> origin feature
# [others] -> real sample -> feature from new packet
temp = []
tempCount = 0

for packet in cap:
    if packet['WLAN'].sa == source:
        nowPacketTime = packet.sniff_time

        if previousPacketTime:
            deltaTime = nowPacketTime - previousPacketTime
            tmp = str(deltaTime).split(':')

            if 'day' in tmp[0]: continue

            hour = int(tmp[0]) * 60 * 60 * 1000
            minute = int(tmp[1]) * 60 * 1000
            second = float(tmp[2]) * 1000
            total = hour + minute + second

            if total >= 1000 and total <= 60 * 1000:
                temp.append(int(total))
                tempCount += 1
                if tempCount % numOfIB == 0:
                    interBurst.append(temp)
                    temp = []

            previousPacketTime = nowPacketTime

        else:
            previousPacketTime = packet.sniff_time

# %%
# check interburst
print('interBurst : ', len(interBurst))
print('interBurst[0] : ', len(interBurst[0]))
# print('realSample : ', len(realSample))
for i in range(len(interBurst)):
    print('interBurst_', i, ' : ', len(interBurst[i]))

# %%
# show inter burst graph
plot_x = [x for x in range(len(interBurst[0]))]
plot_y = [y for y in interBurst[0]]

plt.title('Inter-Burst Latency')
plt.xlabel('(count)')
plt.ylabel('(ms)')

plt.scatter(plot_x, plot_y)
plt.show()

# %%
# get origin feature and show graph about clustering result
df = pd.DataFrame(columns=('x', 'y'))
sortedIB = sorted(interBurst[0])

for i in range(len(sortedIB)):
    df.loc[i] = [i, sortedIB[i]]
data_points = df.values
kmeans = KMeans(n_clusters=numOfCluster).fit(data_points)

# value of center
originFeature = kmeans.cluster_centers_
originFeatureList.append(originFeature)

print('center : ', originFeature)
print('Inter-Burst Latency 평균 값 :', df['y'].mean())
print('Inter-Burst Latency 분산 값 :', df['y'].var())

plt.title('kmeans Test')
plt.xlabel('(count)')
plt.ylabel('(ms)')
plt.scatter(df['x'], df['y'], c=kmeans.labels_.astype(float), s=50)
# plt.scatter(center[:, 0], center[:, 1], c='red', s=50)
plt.show()

# %%
# get feature from another packet
RealSampleFeature = []

for i in range(1, len(interBurst)):
    sortedIB = sorted(interBurst[i])

    for i in range(len(sortedIB)):
        df.loc[i] = [i, sortedIB[i]]
    data_points = df.values
    kmeans = KMeans(n_clusters=numOfCluster).fit(data_points)

    # value of center
    RealSampleFeature.append(kmeans.cluster_centers_)

# %%
# feature contrast -> 새로 들어온 피쳐 기준 (임시)
for i in RealSampleFeature:
    print(euclidean(originFeatureList[0], i))

# %%

## 클러스터링 평가 ##
kmeans = KMeans(n_clusters=numOfCluster)
dbscan = DBSCAN(eps=0.15)
spectral = SpectralClustering(n_clusters=numOfCluster, affinity='nearest_neighbors')
ward = AgglomerativeClustering(n_clusters=numOfCluster)
affinity_propagation = AffinityPropagation(damping=0.9, preference=-200)

clustering_algorithms = (
    ('K-Means', kmeans),
    ('DBSCAN', dbscan),
    ('Spectral Clustering', spectral),
    ('Hierarchical Clustering', ward),
    ('Affinity Propagation', affinity_propagation)
)

# %%
# 
plot_num = 1
plt.figure(figsize=(11, 11))

for j, (name, algorithm) in enumerate(clustering_algorithms):
    with ignore_warnings(category=UserWarning):
        algorithm.fit(data_points)

    if hasattr(algorithm, 'labels_'):
        y_pred = algorithm.labels_.astype(float)
    else:
        y_pred = algorithm.predict(data_points)

    plt.subplot(5, len(clustering_algorithms), plot_num)

    if i == 0:
        plt.title(name)

    plt.scatter(df['x'], df['y'], c=algorithm.labels_.astype(float), s=50)
    plot_num += 1

plt.tight_layout()
plt.show()

# %%

from sklearn.metrics import silhouette_samples

colors = plt.cm.tab10(np.arange(20, dtype=int))
plt.figure(figsize=(6, 8))

for i in range(4):
    model = KMeans(n_clusters=i + 2, random_state=0)
    cluster_labels = model.fit_predict(data_points)
    sample_silhouette_values = silhouette_samples(data_points, cluster_labels)
    silhouette_avg = sample_silhouette_values.mean()

    plt.subplot(4, 2, 2 * i + 1)
    y_lower = 10

    for j in range(i + 2):
        jth_cluster_silhouette_values = sample_silhouette_values[cluster_labels == j]
        jth_cluster_silhouette_values.sort()
        size_cluster_j = jth_cluster_silhouette_values.shape[0]
        y_upper = y_lower + size_cluster_j
        plt.fill_betweenx(np.arange(y_lower, y_upper),
                          0, jth_cluster_silhouette_values,
                          facecolor=colors[j], edgecolor=colors[j])
        plt.text(-0.05, y_lower + 0.5 * size_cluster_j, str(j + 1))
        plt.axvline(x=silhouette_avg, color="red", linestyle="--")
        plt.xticks([-0.2, 0, 0.2, 0.4, 0.6, 0.8, 1])
        plt.yticks([])
        plt.title("Silhouette Coefficient : {:5.2f}".format(silhouette_avg))
        y_lower = y_upper + 10

    plt.subplot(4, 2, 2 * i + 2)
    plt.scatter(df['x'], df['y'], color=colors[cluster_labels], s=5)
    plt.title("Clusters : {}".format(i + 2))

plt.tight_layout()
plt.show()


def main():


if __name__ == '__main__':
    main()
