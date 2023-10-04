namespace CSharpDllInjectDemoWpf.Models
{
    public class DemoStep
    {
        public delegate void StepDelegate();

        public StepDelegate? Step { get; private set; }
        public string? Code { get; set; }
        public string? Description { get; set; }
        public string? Hyperlink { get; set; }
        public bool Current { get;set; }
        public bool NextExecutable { get; set; }

        public bool IsExecutable
        {
            get => Step != null;
        }        

        public DemoStep(StepDelegate? stepDelegate)
        {
            Step = stepDelegate;
        }
    }
}
