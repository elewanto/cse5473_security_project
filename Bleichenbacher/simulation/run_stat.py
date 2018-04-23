import numpy as np
import matplotlib.pyplot as plt

fname = 'stat_1.csv'
dtype1 = np.dtype([('seuqence', np.int), ('type', '|S1'), ('msg_str', 'S1024')])
a = np.loadtxt(fname, delimiter = ', ', dtype=dtype1)

# print(a['msg_str'][:5])

normalised_queried_msg = []
divisor = 2**1008

for m_str in a['msg_str']:
    normalised_queried_msg.append(int(m_str)/divisor )
plt.figure(num='Run I')
plt.plot(a['seuqence'], normalised_queried_msg)
plt.ylabel('normalized decrypted message values')
plt.xlabel('oracle call seuqence')

plt.show()