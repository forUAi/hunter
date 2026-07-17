import express from "express";
import axios from "axios";

const app = express();
app.post("/accounts/:accountId/transfer", async (req, res) => {
  const account = await repository.findById(req.params.accountId);
  await ledger.debit(account, req.body.amount);
  await axios.get(req.body.callbackUrl);
  audit.append(req.params.accountId);
  res.json(account);
});
