from model import *
import matplotlib.pyplot as mp

VEHICLE_COUNT = 1
#RSU_COUNT = 6
TRAFFIC_AUTHORITY_ID = "100"


def simulate(vehicles, sim_size, avg_count, hash_size):
    Base.hash_size = hash_size
    avg_times = []
    for k in range(avg_count):
        times = []
        for i in range(sim_size):
            init = time.time()
            for j in range(sim_size):
                if i != j:
                    vehicles[i].auth_precompute(vehicles[j], 'v2v')
            #vehicles[i].auth_precompute(rsu, 'ch2rsu')
            fin = time.time()
            times.append(fin - init)
        avg_times.append(sum(times) / len(times))

    return avg_times


if __name__ == '__main__':

    sim_size = 20
    avg_size = 50

    ta = TrafficAuthority(TRAFFIC_AUTHORITY_ID)

    user_ids = ['user' + str(i) for i in range(sim_size)]
    passwords = []
    vehicles = []

    # Vehicle Registration
    for i in range(sim_size):
        password = (Base.byte_to_string(Base.generate_random_nonce(Base.hash_size)))
        passwords.append(password)
        r = Base.generate_key(Base.hash_size)
        k = Base.generate_key(Base.hash_size)
        vehicle = Vehicle(user_ids[i], str(i), password, r, k)
        vehicles.append(vehicle)
        vehicle.request_registration(ta)
        vehicle.vehicle_authenticate(str(i), password)
        print("Vehicle", i, "was registered and authenticated")

    print("All 10 vehicles registered!")
    print(passwords)
    print(vehicles)

    times1 = simulate(vehicles, sim_size, avg_size, 160)
    times2 = simulate(vehicles, sim_size, avg_size, 256)
    times3 = simulate(vehicles, sim_size, avg_size, 512)

    ticks = [i for i in range(avg_size)]

    mp.plot(ticks, times1)
    mp.plot(ticks, times2)
    mp.plot(ticks, times3)
    mp.xlabel("Auth Iteration Number")
    mp.ylabel("Avg Auth Time")
    mp.savefig("auth_160vs256vs512_sim_size_" + str(sim_size) + "_avg_" + str(avg_size) + ".png")
