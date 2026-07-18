export async function updateAccount(id: string, body: object) {
  return fetch(`/api/accounts/${id}`, {method: "POST", body: JSON.stringify(body)});
}
