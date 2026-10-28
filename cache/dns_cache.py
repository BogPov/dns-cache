from typing import List, Optional
from pathlib import Path
import time
import pickle

from dns.protocol import DNSRecord, DNSQuestion
from utils.logger import get_logger

log = get_logger()


class DNSCache:
    def __init__(self, cache_file_name: str = 'dns_cache.pkl', auto_save: bool = False):
        self.__store = {}
        self.__filepath = (Path(__file__).parent.parent / "app_data" / cache_file_name).resolve()
        self.__auto_save = auto_save
        self.__load_from_mem()

    def put(self, records: List[DNSRecord]):
        now = time.time()
        for r in records:
            key = (r.name, r.rtype, r.rclass)
            if key not in self.__store:
                self.__store[key] = []
            self.__store[key].append((now, r))

        if self.__auto_save:
            self.save_to_mem()

    def get(self, question: DNSQuestion) -> Optional[List[DNSRecord]]:
        key = (question.name, question.qtype, question.qclass)
        if key not in self.__store:
            return None

        valid_records = []
        now = time.time()

        for ts, rec in self.__store[key]:
            elapsed = now - ts
            if elapsed < rec.ttl:
                new_rec = DNSRecord(rec.name, rec.rtype, rec.rclass, int(rec.ttl - elapsed), rec.rdlength, rec.data)
                valid_records.append(new_rec)

        if valid_records:
            return valid_records

        del self.__store[key]

        if self.__auto_save:
            self.save_to_mem()

        return None

    def __load_from_mem(self):
        if not self.__filepath.exists():
            return

        with open(self.__filepath, 'rb') as f:
            loaded_store = pickle.load(f)
            if loaded_store:
                self.__store = loaded_store
                self.__clean_expired()

    def save_to_mem(self):
        self.__clean_expired()
        with open(self.__filepath, 'wb') as f:
            pickle.dump(self.__store, f)
        
    def __clean_expired(self):
        now = time.time()
        keys_to_delete = []

        for key, records in self.__store.items():
            valid_records = [(ts, rec) for ts, rec in records
                             if (now - ts) < rec.ttl]

            if valid_records:
                self.__store[key] = valid_records
            else:
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del self.__store[key]
