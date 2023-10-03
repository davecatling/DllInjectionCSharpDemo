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
        

        public DemoStep(StepDelegate? stepDelegate)
        {
            Step = stepDelegate;
        }
    }
}
