using Core.Execution;
using Core.Auditing;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
services.AddSingleton<IAuditLogger, NullAuditLogger>();

services.AddSingleton<IActionExecutor, TicketingExecutor>();
services.AddSingleton<IActionExecutor, NotificationExecutor>();
services.AddSingleton<IActionExecutor, FirewallExecutor>();
services.AddSingleton<IActionExecutor, UserAccessExecutor>();
services.AddSingleton<IActionExecutor, HostIsolationExecutor>();

services.AddSingleton<IExecutorRouter, ExecutorRouter>();
services.AddSingleton<IExecutionPipeline, ExecutionPipeline>();

var provider = services.BuildServiceProvider();
_ = provider.GetRequiredService<IExecutionPipeline>();

Console.WriteLine("Execution pipeline configured.");
