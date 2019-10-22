import hashlib
import time
import random
import os


class Base:
    hash_size = 160
    delT = 5

    def __init__(self):
        pass

    @staticmethod
    def hash(hash_input, size):
        '''
        Computes a 160bit hash value for the given input
        :param hash_input: String to be hashed
        :return: 160bit hash value
        '''
        if type(hash_input) is not bytes:
            hash_input = hash_input.encode('utf-8')

        if size == 160:
            return hashlib.sha1(hash_input).hexdigest()
        elif size == 256:
            return hashlib.sha256(hash_input).hexdigest()
        elif size == 512:
            return hashlib.sha512(hash_input).hexdigest()

    @staticmethod
    def sxor(x, y):
        '''
        String XOR
        :return: 160bit XOR of 2 strings
        '''
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(x, y))

    @staticmethod
    def generate_random_nonce(size):
        '''
        :return: A random nonce based on the number of bits
        '''
        return os.urandom(size // 16)

    @staticmethod
    def generate_key(size):
        hash_input = Base.generate_random_nonce(size)
        if size == 160:
            return hashlib.sha1(hash_input).hexdigest()
        elif size == 256:
            return hashlib.sha256(hash_input).hexdigest()
        elif size == 512:
            return hashlib.sha512(hash_input).hexdigest()

    @staticmethod
    def generate_current_timestamp():
        return str(int(time.time()))

    @staticmethod
    def hex_transform(x):
        return ":".join("{:02x}".format(ord(c)) for c in x)

    @staticmethod
    def byte_to_string(x):
        return "".join(chr(c) for c in x)


class TrafficAuthority(Base):
    def __init__(self, id):
        Base.__init__(self)
        self.id = id
        self.registered_rsus = {}
        self.registered_cars = {}
        self.X, self.X_dash = self.generate_1024bit_secret_keys()

    def register_vehicle(self, vehicle_id, masked_password_xor_k, registration_time):
        self.registered_cars[vehicle_id] = registration_time
        pseudo_id = self.hash(vehicle_id + self.X, self.hash_size)
        a1 = self.hash(pseudo_id + self.X, self.hash_size)
        a2 = self.hash(pseudo_id + a1 + self.id, self.hash_size)
        x = self.hash(self.id + self.X, self.hash_size)
        x_dash = self.hash(self.id + self.X_dash, self.hash_size)
        y1 = self.sxor(self.sxor(x, a2), masked_password_xor_k)
        y2 = self.sxor(self.sxor(x_dash, a2), masked_password_xor_k)
        k_v = self.generate_key(160)
        temporal_credential = self.hash(k_v + str(registration_time) + vehicle_id, self.hash_size)
        return pseudo_id, temporal_credential, self.id, y1, y2, a1, a2

    # Need to improve this function
    def generate_1024bit_secret_keys(self):
        x1 = self.generate_key(512)
        x2 = self.generate_key(512)
        x1_dash = self.generate_key(512)
        x2_dash = self.generate_key(512)
        return x1 + x2, x1_dash + x2_dash

class OBU:
    def __init__(self, x, x_dash, pseudo_id, temporal_credential, traffic_authority_id_star):
        self.x = x
        self.x_dash = x_dash
        self.pseudo_id = pseudo_id
        self.temporal_credential = temporal_credential
        self.traffic_authority_id_star = traffic_authority_id_star
        self.session_key = ''


class Vehicle(Base):
    def __init__(self, user_id, id, password, r, k):
        Base.__init__(self)
        self.registration_time = ''
        self.user_id = user_id
        self.id = id
        self.password = password
        self.r = r
        self.k = k
        self.pseudo_id_dash = ''
        self.temporal_credential_dash = ''
        self.traffic_authority_id_dash = ''
        self.b = ''
        self.y = ''
        self.y_dash = ''
        self.a1_dash = ''
        self.a4 = ''
        self.obu = None

    def request_registration(self, traffic_authority):
        self.registration_time = time.time()
        masked_password = self.hash(self.password + self.r, self.hash_size)
        masked_password_xor_k = self.sxor(masked_password, self.k)
        pseudo_id, temporal_credential, traffic_authority_id, y1, y2, a1, a2 = \
            traffic_authority.register_vehicle(self.id,
                                               masked_password_xor_k,
                                               self.registration_time)

        self.b = self.sxor(self.hash(self.password + self.id, self.hash_size), self.r)
        self.a1_dash = self.sxor(a1, self.hash(self.id + self.r, self.hash_size))
        self.traffic_authority_id_dash = self.sxor(self.hash(self.id + self.r, self.hash_size), traffic_authority.id)
        a3 = self.hash(self.id + masked_password + traffic_authority.id + a1, self.hash_size)
        self.a4 = self.hash(a3 + a2, self.hash_size)
        self.pseudo_id_dash = self.sxor(pseudo_id, self.hash(self.password + self.id + self.r, self.hash_size))
        self.temporal_credential_dash = self.sxor(temporal_credential,
                                                  self.hash(self.password + self.r, self.hash_size))
        self.y = self.sxor(y1, self.k)
        self.y_dash = self.sxor(y2, self.k)

    def vehicle_authenticate(self, id, password):
        r_star = self.sxor(self.b, self.hash(password + id, self.hash_size))
        a1_star = self.sxor(self.a1_dash, self.hash(id + r_star, self.hash_size))
        masked_password_star = self.hash(password + r_star, self.hash_size)
        traffic_authority_id_star = self.sxor(self.traffic_authority_id_dash, self.hash(id + r_star, self.hash_size))
        pseudo_id = self.sxor(self.pseudo_id_dash, self.hash(password + id + r_star, self.hash_size))
        a2_star = self.hash(pseudo_id + a1_star + traffic_authority_id_star, self.hash_size)
        x = self.sxor(self.sxor(self.y, a2_star), masked_password_star)
        x_dash = self.sxor(self.sxor(self.y_dash, a2_star), masked_password_star)
        a3_star = self.hash(id + masked_password_star + traffic_authority_id_star + a1_star, self.hash_size)
        a4_star = self.hash(a3_star + a2_star, self.hash_size)
        temporal_credential = self.sxor(self.temporal_credential_dash, masked_password_star)

        # Set the on board variables
        self.obu = OBU(x, x_dash, pseudo_id, temporal_credential, traffic_authority_id_star)

        if a4_star == self.a4:
            print("Authenticated!")
        else:
            print("Can't Authenticate! Could not proceed")
            return

    def auth_precompute(self, item, auth_type):
        r1 = self.byte_to_string(self.generate_random_nonce(self.hash_size))
        t1 = self.generate_current_timestamp()

        # x is used for v2v and x_dash is used for ch2rsu
        x, pseudo_id, temporal_credential, traffic_authority_id_star = None, None, None, None
        if auth_type == 'v2v':
            x, pseudo_id, temporal_credential, traffic_authority_id_star = self.obu.x, self.obu.pseudo_id, self.obu.temporal_credential, self.obu.traffic_authority_id_star
        elif auth_type == 'ch2rsu':
            x, pseudo_id, temporal_credential, traffic_authority_id_star = self.obu.x_dash, self.obu.pseudo_id, self.obu.temporal_credential, self.obu.traffic_authority_id_star

        # Time dependent secret key
        # x and x' as used for v2v auth v2rsu auth
        k_x1 = self.hash(x + t1, self.hash_size)
        d1 = self.hash(r1 + pseudo_id + temporal_credential + t1, self.hash_size)
        m1 = self.sxor(k_x1, d1)
        m2 = self.hash(d1 + traffic_authority_id_star + t1, self.hash_size)

        # Send v2v auth request using an open channel with <m1,m2,t1>
        m5, m4, t2 = None, None, None
        if type(item) == Vehicle:
            m5, m4, t2 = item.auth_authenticate(m1, m2, t1, auth_type)
        elif type(item) == RSU:
            m5, m4, t2 = item.auth_authenticate(m1, m2, t1, traffic_authority_id_star)

        # Check timeliness of reply
        t2_star = self.generate_current_timestamp()

        if abs(int(t2_star) - int(t2)) < self.delT:
            k_x2 = self.hash(x + t2, self.hash_size)
            d2_dash = self.sxor(k_x2, m4)
            self.obu.session_key = self.hash(
                self.hash(x + t1 + t2, self.hash_size) + d1 + d2_dash + traffic_authority_id_star,
                self.hash_size)
            m6 = self.hash(self.obu.session_key + t2, self.hash_size)

            if m6 == m5:
                print("Authenticated", auth_type)

                # Send auth ACK
                t3 = self.generate_current_timestamp()
                m7 = self.hash(self.obu.session_key + t3, self.hash_size)
                ack_status = item.auth_receive_ack(m7, t3)
                print(ack_status)

    def auth_authenticate(self, m1, m2, t1, auth_type):

        t1_star = self.generate_current_timestamp()

        # Retrieve values from OBU
        x, pseudo_id, temporal_credential, traffic_authority_id_star = None, None, None, None
        if auth_type == 'v2v':
            x, pseudo_id, temporal_credential, traffic_authority_id_star = self.obu.x, self.obu.pseudo_id, self.obu.temporal_credential, self.obu.traffic_authority_id_star
        elif auth_type == 'ch2rsu':
            x, pseudo_id, temporal_credential, traffic_authority_id_star = self.obu.x_dash, self.obu.pseudo_id, self.obu.temporal_credential, self.obu.traffic_authority_id_star

        # Check timeliness of the communication
        if abs(int(t1_star) - int(t1)) < self.delT:
            k_x1 = self.hash(x + t1, self.hash_size)
            d1_dash = self.sxor(k_x1, m1)
            m3 = self.hash(d1_dash + traffic_authority_id_star + t1, self.hash_size)

            # Check if m3 == m2
            if m3 == m2:
                r2 = self.byte_to_string(self.generate_random_nonce(self.hash_size))
                t2 = self.generate_current_timestamp()
                k_x2 = self.hash(x + t2, self.hash_size)
                d2 = self.hash(r2 + pseudo_id + temporal_credential + t1 + t2, self.hash_size)
                m4 = self.sxor(k_x2, d2)
                self.obu.session_key = self.hash(
                    self.hash(x + t1 + t2, self.hash_size) + d1_dash + d2 + traffic_authority_id_star,
                    self.hash_size)
                m5 = self.hash(self.obu.session_key + t2, self.hash_size)

                # Return m5,m4,t2 to the other vehicle
                return m5, m4, t2
            else:
                print("Error")
        else:
            print("Timeliness failed")

    def auth_receive_ack(self, m7, t3):

        # Check timeliness
        t3_star = self.generate_current_timestamp()

        if abs(int(t3_star) - int(t3)) < self.delT:
            m8 = self.hash(self.obu.session_key + t3, self.hash_size)
            if m8 == m7:
                print("Ack Successful for Vehicle")
                return True

        return False
