class Accounts { void transfer(String id, int amount) { ledger.save(id, amount); } Ledger ledger; }
interface Ledger { void save(String id, int amount); }
