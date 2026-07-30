const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  const auditLogs = await prisma.auditLog.findMany();
  console.log('Audit logs:', auditLogs);
}

main()
  .catch(e => console.error(e))
  .finally(async () => {
    await prisma.$disconnect();
  });
